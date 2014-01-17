require 'ostruct'
require 'rest_client'
require 'uri'
require 'open3'
require 'io/wait'
require 'timeout'
require 'socket'

module ASM
  module Util

    SERVER_RA_URL='http://localhost:9080/ServerRA/Server'
    # TODO: give razor user access to this directory
    DEVICE_CONF_DIR='/etc/puppetlabs/puppet/devices'

    # See spec/fixtures/asm_server_m620.json for sample response
    def self.fetch_server_inventory(ref_id)
      url = "#{SERVER_RA_URL}/#{ref_id}"
      data = RestClient.get(url, {:accept => :json})
      ret = JSON.parse(data)
      raise(Exception, "Failed to get inventory for server #{ref_id}") if ret['refId'] != ref_id
      ret
    end

    def self.first_host_ip
      Socket.ip_address_list.detect do |intf| 
        intf.ipv4? and !intf.ipv4_loopback? and !intf.ipv4_multicast?
      end.ip_address
    end

    def self.parse_device_config(cert_name)
      conf_file = File.join(DEVICE_CONF_DIR, "#{cert_name}.conf")
      conf_file_data = parse_device_config_file(conf_file)
      uri = URI.parse(conf_file_data[cert_name].url)
      host = uri.host
      user = URI.decode(uri.user)
      password = URI.decode(uri.password)
      { :host => host,
        :user => user,
        :password => password,
        :conf_file_data => conf_file_data }
    end


    # Parse puppet device config files, code cribbed from 
    # Puppet::Util::NetworkDevice::Config
    def self.parse_device_config_file(file)
      begin
        devices = {}
        device = nil
        File.open(file) { |f|
          count = 1
          f.each { |line|
            case line
            when /^\s*#/ # skip comments
              count += 1
              next
            when /^\s*$/  # skip blank lines
              count += 1
              next
            when /^\[([\w.-]+)\]\s*$/ # [device.fqdn]
              name = $1
              name.chomp!
              raise(Exception, "Duplicate device found at line #{count}, already found at #{device.line}") if devices.include?(name)
              device = OpenStruct.new
              device.name = name
              device.line = count
              device.options = { :debug => false }
              devices[name] = device
            when /^\s*(type|url|debug)(\s+(.+))*$/
              parse_device_config_directive(device, $1, $3, count)
            else
              raise(Exception, "Invalid line #{count}: #{line}")
            end
            count += 1
          }
        }
        devices
      end
    end

    def self.parse_device_config_directive(device, var, value, count)
      case var
      when "type"
        device.provider = value
      when "url"
        device.url = value
      when "debug"
        device.options[:debug] = true
      else
        raise(Exception, "Invalid argument '#{var}' at line #{count}")
      end
    end

    def self.run_command_simple(cmd)
      result = {}
      Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
        result['pid']         = wait_thr[:pid]
        result['exit_status'] = wait_thr.value.exitstatus
        result['stdout']      = stdout.read
        result['stderr']      = stderr.read
      end
      result
    end

    def self.run_command(cmd, outfile)
      if File.exists?(outfile)
        raise(Exception, "Cowardly refusing to overwrite #{outfile}")
      end
      File.open(outfile, 'w') do |fh|
        Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
          stdin.close

          # Drain stdout
          while line = stdout.gets
            fh.puts(line)
            # Interleave stderr if available
            while stderr.ready?
              if err = stderr.gets
                fh.puts(err)
              end
            end
          end

          # Drain stderr
          while line = stderr.gets
            fh.puts(line)
          end

          fh.close
          raise(Exception, "#{cmd} failed; output in #{outfile}") unless wait_thr.value.exitstatus == 0
        end
      end
    end

    def self.block_and_retry_until_ready(timeout, exceptions=nil, max_sleep=nil, logger=ASM.logger, &block)
      failures = 0
      sleep_time = 0
      status = Timeout::timeout(timeout) do
        begin
          yield
        rescue Exception => e

          exceptions = Array(exceptions)

          if ! exceptions.empty? and (
             exceptions.include?(key = e.class) or
             exceptions.include?(key = key.name.to_s) or
             exceptions.include?(key = key.to_sym))
          then
            logger.info("Caught exception #{e.class}: #{e}")
            failures += 1
            old_sleep_time = sleep_time
            sleep_time     = (((2 ** failures) -1) * 0.1)
            if max_sleep and (sleep_time > max_sleep)
              sleep old_sleep_time 
            else
              sleep sleep_time
            end
            retry
          else
            # If the exceptions is not in the list of retry_exceptions re-raise.
            raise e
          end
        end
      end
    end

    # ASM services send single-element arrays as just the single element (hash).
    # This method ensures we get a single-element array in that case
    def self.asm_json_array(elem)
      if elem.is_a?(Hash)
        [ elem ]
      else
        elem
      end
    end

    def self.append_resource_configuration!(resource, resources={}, generate_title=nil)
      resource_type = resource['id'] || raise(Exception, 'resource found with no type')
      resource_type.downcase!
      resources[resource_type] ||= {}

      param_hash = {}
      if resource['parameters'].nil?
        raise(Exception, "resource of type #{resource_type} has no parameters")
      else
        resource['parameters'].each do |param|
          if param['value']
            param_hash[param['id'].downcase] = param['value']
          end
        end
      end

      title = param_hash.delete('title')
      if title
        if generate_title
          raise(Exception, "Generated title passed for resource with title #{resource_type}")
        end
      else
        title = generate_title
      end

      raise(Exception, "Component has resource #{resource_type} with no title") unless title

      if resources[resource_type][title]
        raise(Exception, "Resource #{resource_type}/#{title} already existed in resources hash")
      end
      resources[resource_type][title] = param_hash
      resources
    end

    # Build data appropriate for serializing to YAML and using for component
    # configuration via the puppet asm command.
    def self.build_component_configuration(component, generated_title = nil)
      resource_hash = {}
      resources = ASM::Util.asm_json_array(component['resources'])
      resources.each do |resource|
        resource_hash = append_resource_configuration!(resource, resource_hash)
      end
      resource_hash
    end

  end
end
