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
    PUPPET_CONF_DIR='/etc/puppetlabs/puppet'
    DEVICE_CONF_DIR="#{PUPPET_CONF_DIR}/devices"
    DEVICE_SSL_DIR="/var/opt/lib/pe-puppet/devices"
    DATABASE_CONF="#{PUPPET_CONF_DIR}/database.yaml"
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
      url = "#{NETWORKS_RA_URL}/ipAddress/release?usageGUID=#{URI.encode(usage_guid)}"
      data = RestClient.put(url, '')
      true
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
            chassis_username = device_conf[:user]
            chassis_password = device_conf[:password]
            logger.debug "chassis_username : #{chassis_username}"
            if chassis_username == ""
              chassis_username = "root"
              chassis_password = "calvin"
            end
            slot_num = server['slot']
            ioainfo = chassis['ioms']
            ioaslots = Array.new
            ioainfo.each do |ioa|
              ioaip = "dell_iom-"+"#{ioa['managementIP']}"
              ioaslot = ioa['location']
              logger.debug"IOA Location: #{ioaslot}"
              ioaslots.push ioaslot
              ioaips.push ioaip
            end
            logger.debug "ioaips.pushioaips :::: #{ioaips}"
            chassis_info = {'chassis_ip' => chassis_ip, 'chassis_username' => chassis_username, 'chassis_password' => chassis_password, 'slot_num' => slot_num, 'ioaips' => ioaips, 'ioaslots' => ioaslots }
            debug_chassis_info = chassis_info.dup
            debug_chassis_info['chassis_password'] = '******'
            logger.debug "*** chassis_info : #{debug_chassis_info}"
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
      # Have to use IO.popen because jruby popen3 does not accept
      # optional environment hash
      env = { 'PERL_LWP_SSL_VERIFY_HOSTNAME' => '0' }
      cmd = 'env'
      args = ["VI_PASSWORD=#{cluster_device[:password]}",'perl']
      args += [ '-I/usr/lib/vmware-vcli/apps',
        '/opt/Dell/scripts/getVmInfo.pl',
        '--url', "https://#{cluster_device[:host]}/sdk/vimService",
        '--username', cluster_device[:user],
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

    def self.facts_find(cert_name, logger = nil)
      cmd = "sudo puppet facts find '#{cert_name}' --terminus puppetdb --color=false"
      logger.debug("Executing #{cmd}") if logger
      result = run_command_simple(cmd)
      unless result['exit_status'] == 0
        msg = "Failed to find puppet facts for certificate name #{cert_name}"
        logger.error(msg) if logger
        raise(Exception, "#{msg}: #{cmd}: returned #{result.inspect}")
      end
      (JSON.parse(result['stdout']) || {})['values']
    end

    def self.find_equallogic_iscsi_ip(cert_name)
      facts = facts_find(cert_name)
      general = JSON.parse(facts['General Settings'])
      unless general['IP Address']
        raise(Exception, "Could not find iSCSI IP address for #{cert_name}")
      else
        general['IP Address']
      end
    end

    # [TODO] merge with find_equallogic_iscsi_ip
    def self.find_equallogic_iscsi_netmask(cert_name)
      cmd = "sudo puppet facts find '#{cert_name}' "
      result = run_command_simple(cmd)
      unless result['exit_status'] == 0
        msg = "Failed to find puppet facts for certificate name #{cert_name}"
        raise(Exception, "#{msg}: #{cmd}: returned #{result.inspect}")
      end
      facts = (JSON.parse(result['stdout']) || {})['values']
      unless facts['netmask']  # [XXX] there is also a netmask_eth0, using this one for now
        raise(Exception, "Could not find ISCSI netmask for #{cert_name}")
      else
        facts['netmask']
      end
    end


    def self.find_compellent_controller_info(cert_name)
      facts = facts_find(cert_name)
      { 'controller1' => facts['controller_1_ControllerIndex'],
        'controller2' => facts['controller_2_ControllerIndex'] }
    end
    
    def self.find_compellent_volume_info(cert_name, compellent_vol_name, compellent_vol_folder, logger)
      logger.debug("Input compellent volume: #{compellent_vol_name}")
      logger.debug("Input compellent folder: #{compellent_vol_folder}")
      facts = facts_find(cert_name, logger)
      volume_data_json = facts['volume_data']
      unless volume_data_json
        msg = "Facts for compellent array #{cert_name} did not contain volume data"
        logger.error(msg) if logger
        raise(Exception, msg)
      end
      volume_data = JSON.parse(volume_data_json)
      volume_data.each do |volume_info|
        volume = volume_info[1]
        volume.each do |data|
          if (data['Name'][0] == compellent_vol_name)
            volume_device_id = data['DeviceID'][0]
            logger.debug("Compellent volume device id found : #{volume_device_id}")
            return volume_device_id
            break
          end
        end
      end
    end

    def self.first_host_ip
      Socket.ip_address_list.detect do |intf|
        intf.ipv4? and !intf.ipv4_loopback? and !intf.ipv4_multicast?
      end.ip_address
    end

    
    # In case of dual NIC appliance with access to non-routable network
    # method will get the IP address of the appliance which has the access to a particular network
    # ping the destination IP with specific NIC interface to confirm the access
    def self.get_preferred_ip (ipaddress)
      prefered_ip=ipaddress
      ifconfig=`/sbin/ifconfig`
      match=ifconfig.scan(/^(\S+)/)
      match.each do |nic1|
        nic=nic1[0]
        if (nic.to_s.match(/lo\d*/) != nil )
          #Skiping loopback interface
          next
        end

        pingout=`ping -W 1 -c 1 -I "#{nic}" "#{ipaddress}"`
        if (pingout.match(/\s+1\s+received,/) != nil)
          # Get preferent IP
          ifconfig=`/sbin/ifconfig "#{nic}"`
          match_array=ifconfig.scan(/inet addr:(\S+)\s+/m)
          prefered_ip=match_array[0][0]
        end
      end
      prefered_ip
    end

    def self.get_plain_password(encoded_password)
      # NOTE: The actual decryption code in encode_asm.rb is being executed in
      # MRI ruby because it fails in jruby with "OpenSSL::Cipher::CipherError:
      # Illegal key size".
      #
      # Additionally the env command is being used to clear the environment
      # before running MRI ruby to ensure that any torquebox environment
      # variables do not confuse the execution. We saw a few strange cases
      # where jruby gems were being pulled into MRI that were causing
      # decryption failures.
      cmd = "env --ignore-environment /opt/puppet/bin/ruby /opt/asm-deployer/lib/asm/encode_asm.rb #{encoded_password}"
      ret = ASM::Util.run_command_with_args(cmd)
      if ret['exit_status'] != 0
        raise(Exception, "Executing #{cmd} failed: #{ret.inspect}")
      else
        URI.decode(ret['stdout'].strip)
      end
    end
    
    def self.parse_device_config(cert_name)
      conf_file = File.join(DEVICE_CONF_DIR, "#{cert_name}.conf")
      conf_file_data = parse_device_config_file(conf_file)
      uri = URI.parse(conf_file_data[cert_name].url)
      host = uri.host
      user = URI.decode(uri.user)
      enc_password = URI.decode(uri.password)
      { :host => host,
        :user => user,
        :enc_password => enc_password,
        :password => get_plain_password(enc_password),
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

    # Execute esxcli command and parse table into list of hashes. 
    #
    # Example output:
    #
    # [root@dellasm asm-deployer]# esxcli -s 172.25.15.174 -u root -p linux network vswitch standard portgroup list
    # Name                    Virtual Switch  Active Clients  VLAN ID
    # ----------------------  --------------  --------------  -------
    # Management Network      vSwitch0                     1        0
    # vMotion                 vSwitch1                     1       23
    def self.esxcli(cmd_array, endpoint, logger = nil, skip_parsing = false)
      args = ["VI_PASSWORD=#{endpoint[:password]}","esxcli"]
      args += [ '-s', endpoint[:host],
        '-u', endpoint[:user]
      ]
      args += cmd_array.map { |arg| arg.to_s }

      if logger
        tmp = args.dup
        tmp[0] = 'VI_PASSWORD=******' # mask password
        logger.debug("Executing esxcli #{tmp.join(' ')}")
      end

      result = Timeout::timeout(60) do
        ASM::Util.run_command_with_args('env', *args)
      end

      unless result['exit_status'] == 0
        msg = "Failed to execute esxcli command on host #{endpoint[:host]}"
        logger.error(msg) if logger
        args[0] = 'VI_PASSWORD=******' # mask password
        raise(Exception, "#{msg}: esxcli #{args.join(' ')}: #{result.inspect}")
      end

      if skip_parsing
        result['stdout']
      else
        lines = result['stdout'].split(/\n/)
        if lines.size >= 2
          header_line = lines.shift
          seps = lines.shift.split
          headers = []
          pos = 0
          seps.each do |sep|
            header = header_line.slice(pos, sep.length).strip
            headers.push(header)
            pos = pos + sep.length + 2
          end

          ret = []
          lines.each do |line|
            record = {}
            pos = 0
            seps.each_with_index do |sep, index|
              value = line.slice(pos, sep.length).strip
              record[headers[index]] = value
              pos = pos + sep.length + 2
            end
            ret.push(record)
          end
          ret
        end
      end
    end

    def self.run_command_simple(cmd)
      result = {}
      Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
        stdin.close
        result['stdout']      = stdout.read
        result['stderr']      = stderr.read
        result['pid']         = wait_thr[:pid]
        result['exit_status'] = wait_thr.value.exitstatus
      end
      result
    end

    def self.run_command_with_args(cmd, *args)
      result = {}
      # WARNING: jruby-1.7.8 popen3 does not accept optional env argument
      # http://jira.codehaus.org/browse/JRUBY-6966
      Open3.popen3(cmd, *args) do |stdin, stdout, stderr, wait_thr|
        stdin.close
        result['stdout']      = stdout.read
        result['stderr']      = stderr.read
        result['pid']         = wait_thr[:pid]
        result['exit_status'] = wait_thr.value.exitstatus
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

    def self.block_and_retry_until_ready(timeout, exceptions=nil, max_sleep=nil, logger=nil, &block)
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
            exceptions.include?(key = key.to_sym)
         )
            then
            logger.info("Caught exception #{e.class}: #{e}") if logger
            failures += 1
            sleep_time     = (((2 ** failures) -1) * 0.1)
            if max_sleep and (sleep_time > max_sleep)
              sleep_time = max_sleep
            end
            sleep sleep_time
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

    def self.to_boolean(b)
      b == 'true' || b == 'TRUE' || b == true
    end

    def self.append_resource_configuration!(resource, resources={}, options = {})
      options = { 
        :title => nil, 
        :type => resource['id'],
        :decrypt => false
      }.merge(options)

      raise(Exception, 'resource found with no type') unless options[:type]

      options[:type] = options[:type].downcase
      resources[options[:type]] ||= {}

      param_hash = {}
      if resource['parameters'].nil?
        raise(Exception, "resource of type #{options[:type]} has no parameters")
      else
        resource['parameters'].each do |param|
          # HACK: consider any parameter id ending in _network to be a 
          # "network" type. This can go away when we move to using the
          # networkconfiguration type for all network data
          key = param['id'].downcase
          if !key.end_with?('_network')
            param_hash[key] = param['value']
          elsif param['networks'].nil?
            param_hash[key] = nil
          else
            param_hash[key] = self.asm_json_array(param['networks'])
          end
          if param['value'] and param['type'] == 'PASSWORD'
            param_hash['decrypt'] = options[:decrypt]
          end
        end
      end
      title = param_hash.delete('title')
      if options[:type] == 'class'
        title = resource['id']
      end
      if title
        if options[:title]
          raise(Exception, "Generated title (#{options[:title]}) passed for resource with title #{title}")
        end
      else
        title = options[:title]
      end

      raise(Exception, "Component has resource #{options[:type]} with no title") unless title

      if resources[options[:type]][title]
        raise(Exception, "Resource #{options[:type]}/#{title} already existed in resources hash")
      end
      resources[options[:type]][title] = param_hash
      resources
    end

    # Build data appropriate for serializing to YAML and using for component
    # configuration via the puppet asm command.
    #
    # Valid +options+ are :type and :decrypt
    def self.build_component_configuration(component, options = {})
      resource_hash = {}
      resources = ASM::Util.asm_json_array(component['resources'])
      resources.each do |resource|
        resource_hash = append_resource_configuration!(resource, resource_hash, options)
      end
      resource_hash
    end

    def self.sanitize(hash)
      ret = hash.dup
      ret.each do |key, value|
        if value.is_a? (Hash)
          ret[key] = sanitize(value)
        elsif key.to_s.downcase.include? ('password')
          ret[key] = '******'
        end
      end
    end


    # Call to puppet returns list of hots which look like 
    #  + "dell_iom-172.17.15.234" (SHA256) CF:EE:DB:CD:2A:45:17:99:E9:C0:4D:6D:5C:C4:F0:4F:9D:F1:B9:E5:1B:69:3D:99:C2:45:49:5B:0F:F0:08:83
    # this strips all the information and just returns array of host names: "dell_iom-172.17.15.234", "dell_...."
    def self.get_puppet_certs()
      certs_list = []
      results = ASM::Util.run_command_simple("sudo puppet cert list --all")
      unless results['exit_status'] == 0
        raise(Exception, "Call to puppet cert list all failed: \nstdout:#{results['stdout']}\nstderr:#{results['stderr']}\n")
      end
      rslt_str = results['stdout']
      cert_list_array = rslt_str.split('+')
      cert_list_array.delete_at(0)
      cert_list_array.each do |cert|
        certs_list.push(cert.slice(0..(cert.index('(SHA256)')-1)).gsub(/"/,'').strip)
      end
      certs_list
    end

    def self.check_host_list_against_previous_deployments(hostlist)
      dup_certs =  ASM.block_hostlist(hostlist)
      if dup_certs.empty?
        puppet_certs = self.get_puppet_certs
        dup_certs = hostlist & puppet_certs
      end
      dup_certs
    end

    def self.get_logs(id)
      logs = []
      log_file = File.join(ASM.base_dir, id.to_s, 'deployment.log')
      return nil unless File.exists?(log_file)
      File.open(log_file, 'r').each_line do |line|
        if line =~ /^\w, \[(.*?)\]\s+(\w+) -- : (.*)/
          log = {'msg' => $3, 'datetime' => $1, 'severity' => $2}
          logs.push(log) unless log['severity'] == 'DEBUG'
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

    def self.hostname_to_certname(hostname)
      hostname.downcase!
      hostname.gsub!(/[*'_\/!~`@#%^&()$]/,'')
      hostname = 'agent-'+hostname
    end

    def self.get_report(id, certname)
      report_dir = File.join(ASM.base_dir,
                             id.to_s,
                             'resources',
                             'state',
                             certname
                             )
      report_file = File.join(report_dir, 'last_run_report.yaml')
      out_file    = File.join(report_dir, 'last_run_report_summary.yaml')
      result = run_command_simple("sudo puppet asm summarize_report --infile #{report_file} --outfile #{out_file}")
      unless result['exit_status'] == 0
        raise(Exception, "Command failed: stdout #{result['stdout']} stderr:#{result['stderr']}")
      end     
      YAML.load_file(out_file)

    end

    def self.get_puppet_log(id, certname)
      log_file = File.join(ASM.base_dir, id.to_s, "#{certname}.out")
      File.read(log_file)
    end

  end
end
