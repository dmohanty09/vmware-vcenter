require 'asm/errors'
require 'asm/util'
require 'json'
require 'rest_client'
require 'hashie'

module ASM
  class Razor

    RAZOR_API_URL = 'http://localhost:8081/api'

    attr_reader :logger

    def initialize(options = {})
      options = {
          :api_url => RAZOR_API_URL,
          :logger => nil,
      }.merge(options)
      @api_url = options[:api_url]
      @logger = options[:logger]
    end

    def get(type, *name_and_args)
      begin
        url = [@api_url, 'collections', type, *name_and_args].join('/')
        response = RestClient.get(url)
        if response.code.between?(200, 299)
          result = JSON.parse(response)
          result.include?('items') ? result['items'] : result
        else
          raise(ASM::CommandException, "Bad http code: #{response.code}:\n#{response.to_str}")
        end
      rescue RestClient::ResourceNotFound => e
        raise(ASM::CommandException, "Rest call to #{url} failed: #{e}")
      end
    end

    def find_node(serial_num)
      matches = get('nodes').collect { |node| get('nodes', node['name']) }.find_all do |details|
        details.extend Hashie::Extensions::DeepFetch
        details.deep_fetch('hw_info', 'serial') { |k| nil } == serial_num.downcase
      end

      if matches.size <= 1
        matches.first
      else
        dups = matches.collect {|n| n['name']}.join(', ')
        raise(Exception, "Multiple razor node matches found for serial number #{serial_num}: #{dups}")
      end
    end

    def find_host_ip(serial_num)
      node = find_node(serial_num)
      if node
        node.extend Hashie::Extensions::DeepFetch
        node.deep_fetch('facts', 'ipaddress') { |k| nil }
      end
    end

    def find_node_blocking(serial_num, timeout)
      max_sleep = 30
      ASM::Util.block_and_retry_until_ready(timeout, ASM::CommandException, max_sleep) do
        find_node(serial_num) or
            raise(ASM::CommandException,
                  'Did not find our node by its serial number. Will try again')
      end
    end

    STATUS_ORDER = [nil, :microkernel, :bind, :reboot, :boot_install, :boot_local, :boot_local_2,]

    class InvalidStatusException < Error;
    end

    def cmp_status(status_1, status_2)
      index_1 = STATUS_ORDER.find_index(status_1) or raise(InvalidStatusException, "Invalid status: #{status_1}")
      index_2 = STATUS_ORDER.find_index(status_2) or raise(InvalidStatusException, "Invalid status: #{status_2}")
      index_1 <=> index_2
    end

    # Given a node name, returns the status of the install of the O/S
    # corresponding to policy_name, or nil if none is found.
    #
    # Possible statuses (in order of occurrence) are:
    #   :microkernel - node has booted the razor microkernel
    #   :bind - razor policy has been attached to the node
    #   :reboot - node has rebooted to begin running O/S installer
    #   :boot_install - node has booted into the O/S installer
    #   :boot_local - install has completed and node has booted into O/S
    #   :boot_local_2 - node has booted into O/S a second time. (In the case
    #                   of ESXi the install is not complete until this event)
    #
    # Works by going through the razor node logs and looking at events between
    # the bind and reinstall events for the given policy_name. If the
    # policy_name is reused for more than one install this will cause p
    def task_status(node_name, policy_name)
      logs = get('nodes', node_name, 'log')
      result = nil
      n_boot_local = 0
      logs.each do |log|
        # Check for policy-related events
        timestamp = Time.parse(log['timestamp'])
        case log['event']
          when 'bind'
            if log['policy'] == policy_name
              result = {:status=> :bind, :timestamp => timestamp}
            else
              result = {:status=> nil, :timestamp => timestamp}
            end
            n_boot_local = 0
          when 'reinstall'
            result = {:status=> nil, :timestamp => timestamp}
          when 'boot'
            if result
              case log['template']
                when 'boot_install'
                  result = {:status=> :boot_install, :timestamp => timestamp}
                when 'boot_wim' # for windows
                  result = {:status=> :boot_install, :timestamp => timestamp}
                when 'boot_local'
                  if n_boot_local == 0
                    result = {:status=> :boot_local, :timestamp => timestamp}
                  else
                    result = {:status=> :boot_local_2, :timestamp => timestamp}
                  end
                  n_boot_local += 1
                else
                  logger.warn("Unknown boot template #{log['template']}") if logger
              end
            elsif log['task'] == 'microkernel'
              # NOTE: The bind event has not occurred yet, so we don't really know
              # if this event will result in progress towards installing the specified
              # policy. Nevertheless this is useful status information, i.e.
              # that razor is progressing.
              result = {:status=> :microkernel, :timestamp => timestamp}
            end
          else
            if result && log['action'] == 'reboot' && log['policy'] == policy_name
              result = {:status=> :reboot, :timestamp => timestamp}
            end
        end
      end
      result
    end

    def os_name(task_name)
      case
        when task_name.start_with?('vmware')
          'VMWare ESXi'
        when task_name.start_with?('windows')
          'Windows'
        when task_name.start_with?('redhat')
          'Red Hat Linux'
        when task_name.start_with?('ubuntu')
          'Ubuntu Linux'
        when task_name.start_with?('debian')
          'Debian Linux'
        else
          task_name
      end
    end

    def block_until_task_complete(serial_number, policy_name, task_name, terminal_status = nil)
      # The vmware ESXi installer has to reboot twice before being complete
      terminal_status ||= if task_name.start_with?('vmware') || task_name.start_with?('windows')
                            :boot_local_2
                          else
                            :boot_local
                          end
      logger.debug("Waiting for server #{serial_number} to PXE boot") if logger
      node = find_node_blocking(serial_number, 600) or
          raise(UserException, "Server #{serial_number} failed to PXE boot")

      os_name = os_name(task_name)

      # Max time to wait at each stage
      max_times = {nil => 300,
                   :microkernel => 300,
                   :bind => 300,
                   :reboot => 300,
                   # for esxi / linux most of the install happens in :boot_install
                   :boot_install => 2700,
                   # for windows most of the install happens in :boot_local
                   :boot_local => 2700,
                   :boot_local_2 => 600}
      status = nil
      result = nil
      while cmp_status(status, terminal_status) < 0
        timeout = max_times[status] or raise(Exception, "Invalid status #{status}")
        begin
          result = new_status = ASM::Util.block_and_retry_until_ready(timeout, ASM::CommandException, 60) do
            temp_status = task_status(node['name'], policy_name)
            logger.debug("Current install status for server #{serial_number} and policy #{policy_name} is #{temp_status[:status]}") if logger
            if temp_status[:status] == status
              raise(ASM::CommandException, "Task status remains #{status}")
            else
              temp_status
            end
          end
          result = new_status
          if new_status[:status] == status
            raise(UserException, "Server #{serial_number} O/S install has failed to make progress, aborting.")
          else
            status = new_status[:status]
          end

          logger.debug("Server #{serial_number} O/S status has progressed to #{status}") if logger
          msg = case status
                  when :bind
                    "Server #{serial_number} has been configured to boot the #{os_name} installer"
                  when :boot_install
                    "Server #{serial_number} has rebooted into the #{os_name} installer"
                  when status == terminal_status
                    "Server #{serial_number} has completed installation of #{os_name}"
                  else
                    logger.debug("Server #{serial_number} task installer status is #{status}") if logger
                    nil
                end
          logger.info(msg) if msg && logger
        rescue Timeout::Error
          raise(UserException, "Server #{serial_number} O/S install timed out")
        end
      end
      result
    end

  end
end
