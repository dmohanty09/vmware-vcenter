require 'pathname'
require 'rexml/document'

module ASM
  module WsMan

    # Wrapper for the wsman client. endpoint should be a hash of
    # :host, :user, :password
    def self.invoke(endpoint, method, schema, options = {})
      options = {
        :selector => nil,
        :props => {},
        :input_file => nil,
        :logger => nil,
      }.merge(options)
      
      cmd = 'wsman'
      if method == 'enumerate'
        args = [ 'enumerate', schema ]
      else
        args = [ 'invoke', '-a', method, schema ]
      end

      args += [ '-h', endpoint[:host],
                '-V', '-v', '-c', 'dummy.cert', '-P', '443',
                '-u', endpoint[:user], '-p', endpoint[:password],
                '-j', 'utf-8', '-y', 'basic', ]
      if options[:input_file]
        args += [ '-J', options[:input_file] ]
      end
      options[:props].each do |key, val|
        args += [ '-k', "#{key}=#{val}" ]
      end

      if options[:logger]
        masked_args = args.dup
        masked_args[args.find_index('-p') + 1] = '******'
        options[:logger].debug("Executing #{cmd} #{masked_args.join(' ')}")
      end
      result = ASM::Util.run_command_with_args(cmd, *args)
      options[:logger].debug("Result = #{result}") if options[:logger]
      
      unless result['exit_status'] == 0
        if result['stdout'] =~ /Authentication failed/
          msg = "Authentication failed, please retry with correct credentials after resetting the iDrac at #{endpoint[:host]}."
        elsif result['stdout'] =~ /Connection failed./
          msg = "Connection failed, Couldn't connect to server. Please check IP address credentials for iDrac at #{endpoint[:host]}."
        else
          msg = "Failed to execute wsman command against server #{endpoint[:host]}"
        end
        options[:logger].error(msg) if options[:logger]
        raise(Exception, "#{msg}: #{result}")
      end
      
      if options[:selector]
        doc = REXML::Document.new(result['stdout'])
        node = REXML::XPath.first(doc, options[:selector])
        if node
          node.text
        else
          msg = "Invalid WS-MAN response from server #{endpoint[:host]}"
          options[:logger].error(msg) if options[:logger]
          raise(Exception, msg)
        end
      else
        result['stdout']
      end
    end

    def self.reboot(endpoint, logger = nil)
      # Create the reboot job
      logger.debug("Rebooting server #{endpoint[:host]}") if logger
      input_file = File.join(Pathname.new(__FILE__).parent, 'reboot.xml')
      instanceid = invoke(endpoint, 
                          'CreateRebootJob',
                          'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_SoftwareInstallationService?CreationClassName=DCIM_SoftwareInstallationService,SystemCreationClassName=DCIM_ComputerSystem,SystemName=IDRAC:ID,Name=SoftwareUpdate',
                          :selector =>'//wsman:Selector Name="InstanceID"',
                          :props => { 'RebootJobType' => '2' },
                          :input_file => input_file,
                          :logger => logger)
      
      # Execute job
      jobmessage = invoke(endpoint,
                          'SetupJobQueue',
                          'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_JobService?CreationClassName=DCIM_JobService,Name=JobService,SystemName=Idrac,SystemCreationClassName=DCIM_ComputerSystem',
                          :selector => '//n1:Message',
                          :props => { 
                            'JobArray' => instanceid,
                            'StartTimeInterval' => 'TIME_NOW' 
                          },
                          :logger => logger)
      logger.debug "Job Message #{jobmessage}" if logger
      return true
    end
    
    def self.get_power_state(endpoint, logger = nil)
      # Create the reboot job
      logger.debug("Getting the power state of the server with iDRAC IP: #{endpoint[:host]}") if logger
      response = invoke(endpoint,
                        'enumerate',
                        'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/DCIM_CSAssociatedPowerManagementService',
                        :logger => logger)
      updated_xml = match_array=response.scan(/(<\?xml.*?<\/s:Envelope>?)/m)
      xmldoc = REXML::Document.new(updated_xml[1][0])
      powerstate_node = REXML::XPath.first(xmldoc, '//n1:PowerState')
      powerstate = powerstate_node.text
      logger.debug("Power State: #{powerstate}") if logger
      powerstate
    end
    
    def self.get_wwpns(endpoint, logger = nil)
      # TODO do we need to specify this external link?
      # it makes it seem this has an external dependency
      # on network connectivity which we know is not
      # true
      wsmanCmdResponse = invoke(endpoint, 'enumerate',
                                'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/DCIM/DCIM_FCView',
                                :logger => logger)
      wsmanCmdResponse.split(/\n/).collect do |ele|
        if ele =~ /<n1:VirtualWWPN>(\S+)<\/n1:VirtualWWPN>/
          $1
        end
      end.compact
    end

    def self.get_mac_addresses(endpoint, servermodel, logger = nil)
      servermodel = servermodel.downcase
      if servermodel == 'r720'
        nicNames = [ 'NIC.Slot.2-1-1', 'NIC.Slot.2-2-1' ]
      elsif [ 'm620', 'm420', 'm820', 'r620' ].include?(servermodel)
        nicNames = [ 'NIC.Integrated.1-1-1', 'NIC.Integrated.1-2-1' ]
      else
        logger.debug("Unsupported server model #{servermodel}") if logger
        nicNames = nil
      end
      
      ret = []
      if nicNames
        resp = invoke(endpoint, 'enumerate', 
                      'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_NICView',
                      :logger => logger)
        
        mac_address = nil
        resp.split("\n").each do |line|
          # Expect to find alternating lines of CurrentMacAddress and FQDD
          # where FQDD is the nic name. Only include macs from known nicNames.
          if line =~ /<n1:CurrentMACAddress>(\S+)\<\/n1:CurrentMACAddress>/
            mac_address = $1
          elsif line =~ /<n1:FQDD>(\S+)<\/n1:FQDD>/
            nicName = $1
            if (nicNames.include?(nicName))
              if mac_address
                logger.debug "MAC to be pushed #{mac_address}" if logger
                ret.push(mac_address)
              else
                logger.debug("No mac address set when nic #{nicName} seen") if logger
              end
            end
            mac_address = nil
          end
        end
      end
      
      logger.debug("********* MAC Address List is #{ret} **************") if logger
      ret
    end

  end
end
