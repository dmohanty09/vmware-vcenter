require 'io/wait'
require 'json'
require 'open3'
require 'ostruct'
require 'rest_client'
require 'socket'
require 'timeout'
require 'uri'

module ASM
  module Util

    SERVER_RA_URL='http://localhost:9080/ServerRA/Server'
    NETWORKS_RA_URL='http://localhost:9080/VirtualServices/Network'
    CHASSIS_RA_URL='http://localhost:9080/ChassisRA/Chassis'
    # TODO: give razor user access to this directory
    DEVICE_CONF_DIR='/etc/puppetlabs/puppet/devices'
    # See spec/fixtures/asm_server_m620.json for sample response
    #
    # cert_name is in format devicetype-servicetag
    def self.fetch_server_inventory(cert_name)
      service_tag_lower = /^[^-]+-(.*)$/.match(cert_name)[1]
      service_tag = service_tag_lower.upcase
      url = "#{SERVER_RA_URL}/?filter=eq,serviceTag,#{service_tag}"
      data = RestClient.get(url, {:accept => :json})
      ret = JSON.parse(data)
      # should return a list of one element with matching serviceTag
      if !ret || ret.size != 1 || ret[0]['serviceTag'] != service_tag
        raise(Exception, "Failed to get inventory for server #{cert_name}")
      end
      ret[0]
    end

    def self.fetch_network_settings(guid)
      url = "#{NETWORKS_RA_URL}/#{guid}"
      data = RestClient.get(url, {:accept => :json})
      ret = JSON.parse(data)
      if ret['id'] != guid
        raise(Exception, "Failed to retrieve network settings for guid #{guid}: #{ret.to_yaml}")
      else
        ret
      end
    end

    def self.reserve_network_ips(guid, n_ips, usage_guid)
      url = "#{NETWORKS_RA_URL}/ipAddress/assign?networkId=#{URI.encode(guid)}&numberToReserve=#{n_ips}&usageGUID=#{URI.encode(usage_guid)}"
      data = RestClient.put(url, {:content_type => :json}, {:accept => :json})
      ret = JSON.parse(data)
      n_retrieved = !ret ? 0 : ret.size
      if n_retrieved != n_ips
        raise(Exception, "Retrieved invalid response to network reservation request: #{ret}")
      end
      ret
    end

    def self.release_network_ips(usage_guid)
      url = "#{NETWORKS_RA_URL}/ipAddress/release?usageGUID=#{usage_guid}"
      data = RestClient.put(url, '')
      ret = JSON.parse(data)
    end

    def self.chassis_inventory(server_cert_name, logger)
      chassis_info = {}
      ioaips = []
      url = "#{CHASSIS_RA_URL}"
      logger.debug "URL : #{url}"
      data = RestClient.get(url, {:accept => :json})
      ret = JSON.parse(data)
      ret.each do |chassis|
        logger.debug "chassis : #{chassis}"
        serverinfo = chassis['servers']
        logger.debug "***************serverinfo #{serverinfo}"
        serverinfo.each do |server|
          logger.debug "server : #{server} : server_cert_name : #{server_cert_name}"
          if server['serviceTag'] == server_cert_name
            # Got chassis. get chassis information
            chassis_ip = chassis['managementIP']
            credentialRefId = chassis['credentialRefId']
            chassisvervicetag = chassis['serviceTag']
            chassisvervicetag = chassisvervicetag.downcase
            chassisvertname = "chassism1000e-"+"#{chassisvervicetag}"
            logger.debug "************chassisvertname : #{chassisvertname}"
            device_conf ||= ASM::Util.parse_device_config(chassisvertname)
            logger.debug "******** In getServerInventory device_conf is #{device_conf}************\n"

            #            device_conf ||= ASM::Util.parse_device_config(certname)
            #            inv  ||= ASM::Util.fetch_server_inventory(certname)
            #            logger.debug "******** In getServerInventory device_conf is #{device_conf}************\n"
            #            logger.debug "******** In getServerInventory inv is #{inv} **************\n"
            chassis_username = device_conf[:user]
            chassis_password = device_conf[:password]
            logger.debug "chassis_username : #{chassis_username} chassis_password #{chassis_password}"
            if chassis_username == ""
              chassis_username = "root"
              chassis_password = "calvini"
            end
            slot_num = server['slot']
            ioainfo = chassis['ioms']
            ioainfo.each do |ioa|
              ioaip = "dell_iom-"+"#{ioa['managementIP']}"
              ioaips.push ioaip
            end
            logger.debug "ioaips.pushioaips :::: #{ioaips}"
            chassis_info = {'chassis_ip' => chassis_ip, 'chassis_username' => chassis_username, 'chassis_password' => chassis_password, 'slot_num' => slot_num, 'ioaips' => ioaips }
            logger.debug "*** chassis_info : #{chassis_info}"
            break
          end
        end
      end
      return chassis_info
    end
    
    def self.get_iom_type(server_cert_name,iom_cert_name, logger)
      chassis_info = {}
      url = "#{CHASSIS_RA_URL}"
      logger.debug "URL : #{url}"
      data = RestClient.get(url, {:accept => :json})
      ret = JSON.parse(data)
      ret.each do |chassis|
        serverinfo = chassis['servers']
        serverinfo.each do |server|
          logger.debug "server : #{server} : server_cert_name : #{server_cert_name}"
          updated_service_tag = server['serviceTag'].downcase
          logger.debug "updated_service_tag :: #{updated_service_tag} *** server_cert_name : #{server_cert_name}"
          if server_cert_name.downcase == updated_service_tag.downcase
            logger.debug "Found the matching server #{server['serviceTag']}"
            # Got chassis. get chassis information
            chassis_ip = chassis['managementIP']
            chassisvervicetag = chassis['serviceTag']
            chassisvervicetag = chassisvervicetag.downcase
            ioainfo = chassis['ioms']
            logger.debug "IOM info: #{ioainfo}"
            ioainfo.each do |ioa|
              ioaip = "dell_iom-"+"#{ioa['managementIP']}"
              model = ioa['model']
              if ioaip == iom_cert_name
                if model =~ /Aggregator/
                  ioatype = "ioa"
                elsif model =~ /MXL/
                  ioatype = "mxl"
                end
                return ioatype
              end
            end
          end
        end
      end
    end


    # Execute getVmInfo.pl script to find UUID for given VM name
    #
    # TODO: this will break if there is more than one VM with same name
    #
    # Sample output of perl script:
    #
    # VM uuid :423b35e8-61ef-3d16-5fae-75c189f4711b
    # VM power State :poweredOn
    # VM committed size :17244304694
    # VM Total number of Ethernet Cards :1
    # VM Provisioned size :83.3303845431656
    # VMNicNetworkMapping=1:HypMan28|*
    def self.find_vm_uuid(cluster_device, vmname)
      # Have to use env command because jruby popen3 does not accept
      # optional environment hash
      env = { 'PERL_LWP_SSL_VERIFY_HOSTNAME' => '0' }
      cmd = 'perl'
      args = [ '-I/usr/lib/vmware-vcli/apps',
        '/opt/Dell/scripts/getVmInfo.pl',
        '--url', "https://#{cluster_device[:host]}/sdk/vimService",
        '--username', cluster_device[:user],
        '--password', cluster_device[:password],
        '--vmName', vmname,
      ]

      stdout = nil
      IO.popen([ env, cmd, *args]) do |io|
        stdout = io.read
      end

      raise(Exception, "Failed to execute getVmInfo.pl") unless stdout

      # Parse output into key-value pairs
      result_hash = {}
      stdout.lines.each do |line|
        kv = line.split(/:/, 2).map(&:strip)
        if kv and kv.size == 2
          result_hash[kv[0]] = kv[1]
        end
      end

      raise(Exception, "Failed to find UUID from output: #{stdout}") unless result_hash['VM uuid']

      result_hash['VM uuid']
    end

    # Hack to figure out cert name from uuid.
    #
    # For UUID 4223-c288-0e73-104e-e6c0-31f5f65ad063
    # Shows up in puppet as VMware-42 23 c2 88 0 e 73 10 4 e-e6 c0 31 f5 f6 5 a d0 63
    def self.vm_uuid_to_serial_number(uuid)
      without_dashes = uuid.gsub(/-/, '')
      raise(Exception, "Invalid uuid #{uuid}") unless without_dashes.length == 32
      first_half = []
      last_half = []
      ( 0 .. 7 ).each do |i|
        start = i * 2
        first_half.push(without_dashes[start .. start + 1])
        start = i * 2 + 16
        last_half.push(without_dashes[start .. start + 1])
      end
      "VMware-#{first_half.join(' ')}-#{last_half.join(' ')}"
    end

    def self.find_equallogic_iscsi_ip(cert_name)
      cmd = 'sudo'
      args = [ 'puppet', 'facts', 'find', cert_name,
        '--terminus', 'yaml',
        '--clientyamldir=/var/opt/lib/pe-puppet/yaml', ]
      result = self.run_command_with_args(cmd, *args)
      raise(Exception, "Failed to fetch puppet facts for #{cert_name}") unless result['exit_status'] == 0
      facts = (JSON.parse(result['stdout']) || {})['values']
      general = JSON.parse(facts['General Settings'])
      unless general['IP Address']
        raise(Exception, "Could not find iSCSI IP address for #{cert_name}")
      else
        general['IP Address']
      end
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
        :url => uri,
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

    def self.run_command_with_args(cmd, *args)
      result = {}
      # WARNING: jruby-1.7.8 popen3 does not accept optional env argument
      # http://jira.codehaus.org/browse/JRUBY-6966
      Open3.popen3(cmd, *args) do |stdin, stdout, stderr, wait_thr|
        result['pid']         = wait_thr[:pid]
        result['exit_status'] = wait_thr.value.exitstatus
        result['stdout']      = stdout.read
        result['stderr']      = stderr.read
      end
      result
    end

    def self.run_command(cmd, outfile)
      # Need to update the content of the file while creating
      # multiple manifest files
      #if File.exists?(outfile)
      #  raise(Exception, "Cowardly refusing to overwrite #{outfile}")
      #end
      File.open(outfile, 'a') do |fh|
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
    def self.build_component_configuration(component)
      resource_hash = {}
      resources = ASM::Util.asm_json_array(component['resources'])
      resources.each do |resource|
        resource_hash = append_resource_configuration!(resource, resource_hash)
      end
      resource_hash
    end

    def self.get_logs(id)
      logs = []
      log_file = File.join(ASM.base_dir, id.to_s, 'deployment.log')
      return nil unless File.exists?(log_file)
      File.open(log_file, 'r').each_line do |line|
        if line =~ /^\w, \[(.*?)\]  \w+ -- : (.*)/
          logs.push({'msg' => $2, 'datetime' => $1})
        else
          ASM.logger.warn("Unexpected log line: #{line}")
        end
      end
      logs
    end

    def self.get_status(id)
      logs = get_logs(id)
      if logs
        status = nil
        logs.reverse.each do |log|
          if log['msg'] =~ /^Status: (.*)$/
            return $1
          end
        end
        if logs.size == 0
          'Unknown'
        else
          raise(Exception, 'We have logs, but no status. This is not supposed to happen')
        end
      else
        'Unknown'
      end
    end

  end
end
