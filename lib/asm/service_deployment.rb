require 'asm'
require 'asm/util'
require 'fileutils'
require 'json'
require 'logger'
require 'open3'
require 'rest_client'
require 'timeout'
require 'yaml'
require 'set'
require 'asm/GetWWPN'
require 'fileutils'
require 'asm/get_switch_information'

$serverhash = Hash.new
$switchhash = Hash.new
$server_vlan_info = Hash.new
$configured_rack_switches = Array.new
$configured_blade_switches = Array.new

class ASM::ServiceDeployment
  class CommandException < Exception; end

  class SyncException < Exception; end

  def initialize(id)
    unless id
      raise(Exception, "Service deployment must have an id")
    end
    @id = id
  end

  def logger
    @logger ||= create_logger
  end

  def log(msg)
    logger.info(msg)
  end

  def debug=(debug)
    @debug = debug
  end

  def process(service_deployment)
    begin
      # Before we go multi-threaded, check whether puppet broker exists
      # and create it if needed
      @puppet_broker = create_broker_if_needed

      ASM.logger.info("Deploying #{service_deployment['deploymentName']} with id #{service_deployment['id']}")
      log("Status: Started")
      log("Starting deployment #{service_deployment['deploymentName']}")

      # Write the deployment to filesystem for ease of debugging / reuse
      File.open(File.join(deployment_dir, 'deployment.json'), 'w') do |file|
        file.write(JSON.pretty_generate({ "Deployment" => service_deployment }))
      end

      # TODO: pass deployment into constructor instead of here
      @deployment = service_deployment

      # Will need to access other component types during deployment
      # of a given component type in the future, e.g. VSwitch configuration
      # information is contained in the server component type data
      @components_by_type = components_by_type(service_deployment)
      #$configured_rack_switches = get_all_rack_switches()
      #$configured_blade_switches = get_all_blade_switches()
      get_all_switches()
      process_components()
    rescue Exception => e
      File.open(File.join(deployment_dir, "exception.log"), 'w') do |fh|
        fh.puts(e.inspect)
        fh.puts
        (e.backtrace || []).each { |line| fh.puts(line) }
      end
      log("Status: Error")
      raise(e)
    end
    log("Status: Completed")
  end

  def components_by_type(service_deployment)
    components_by_type = {}
    if service_deployment['serviceTemplate']
      unless service_deployment['serviceTemplate']['components']
        logger.warn("service deployment data has no components")
      end
    else
      logger.warn("Service deployment data has no serviceTemplate defined")
    end

    components = ASM::Util.asm_json_array((service_deployment['serviceTemplate'] || {})['components'] || [])

    logger.debug("Found #{components.length} components")
    components.each do |component|
      logger.debug("Found component id #{component['id']}")
      components_by_type[component['type']] ||= []
      components_by_type[component['type']].push(component)
    end
    components_by_type
  end

  def process_components()
    ['STORAGE', 'TOR', 'SERVER', 'CLUSTER', 'VIRTUALMACHINE', 'SERVICE', 'TEST'].each do |type|
      if components = @components_by_type[type]
        log("Processing components of type #{type}")
        log("Status: Processing_#{type.downcase}")
        components.collect do |comp|
          #
          # TODO: this is some pretty primitive thread management, we need to use
          # something smarter that actually uses a thread pool
          #
          Thread.new do
            raise(Exception, 'Component has no certname') unless comp['id']
            send("process_#{type.downcase}", comp)
          end
        end.each do |thrd|
          thrd.join
        end
        log("Finsished components of type #{type}")
      end
    end
  end

  def process_generic(cert_name, config, puppet_run_type, override = true)
    raise(Exception, 'Component has no certname') unless cert_name
    log("Starting processing resources for endpoint #{cert_name}")

    resource_file = File.join(resources_dir, "#{cert_name}.yaml")

    wwpn = ""
    wwpnSet = Set.new()
    File.open(resource_file, 'w') do |fh|
      fh.write(config.to_yaml)
    end
    if ( cert_name =~ /(.*)[C|c]ompellent(.*)/ )
      wwpnSet = process_compellent

      myfile = File.open(resource_file, "r+")

      time = Time.now.to_i
      tempfileloc = "/tmp/temp#{time}.txt"
      mytempfile = File.open(tempfileloc, "w")

      myfile.each do |line|
        if ( line =~ /(.*)wwn\:(.*)/ )
          data = line.scan(/wwn\:(.*)/)
          #data = data.gsub!(/\"/, "")
          temp = data[0]
          temp1 = temp[0]
          temp2=temp1.strip
          wwpnstring = temp2.split(',')
          #for each_wwpnstring in wwpnstring
          wwpnstring.each do | each_wwpnstring |
            if each_wwpnstring.length > 0
              wwpnSet.add("#{each_wwpnstring}")
            end
          end
        else
          mytempfile.puts("#{line}")
        end
      end

      myfile.close
      mytempfile.close

      wwpnSet.each do |wwpndata|
        wwpndata = wwpndata.gsub(/:/, '')
        if wwpn.to_s.strip.length == 0
          wwpn = "#{wwpndata}"
        else
          if wwpndata.to_s.strip.length > 4
            wwpn.concat( ",#{wwpndata}")
          end
        end
      end

      File.open(tempfileloc,"a") do |tempfile|
        tempfile.puts("    wwn: '#{wwpn}'")
        tempfile.close
      end
      FileUtils.mv(tempfileloc, resource_file)
    end

    override_opt = override ? "--always-override " : ""
    cmd = "sudo puppet asm process_node --debug --trace --filename #{resource_file} --run_type #{puppet_run_type} #{override_opt}#{cert_name}"
    if @debug
      logger.info("[DEBUG MODE] execution skipped for '#{cmd}'")
    else
      puppet_out = File.join(deployment_dir, "#{cert_name}.out")
      if puppet_run_type == 'device'
        begin
          timeout = 300
          start = Time.now
          yet_to_run_command = true
          while(yet_to_run_command)
            if ASM.block_certname(cert_name)
              yet_to_run_command = false
              logger.debug "Executing the command"
              ASM::Util.run_command(cmd, puppet_out)
            else
              sleep 2
              if Time.now - start > 300
                raise(SyncException, "Timed out waiting for a lock for device cert #{cert_name}")
              end
            end
          end
        rescue Exception => e
          unless e.class == SyncException
            ASM.unblock_certname(cert_name)
          end
          raise(e)
        end
        ASM.unblock_certname(cert_name)
      else
        ASM::Util.run_command(cmd, puppet_out)
      end
      results = {}
      found_result_line = false
      File.readlines(puppet_out).each do |line|
        if line =~ /Results: For (\d+) resources\. (\d+) from our run failed\. (\d+) not from our run failed\. (\d+) updated successfully\./
          results = {'num_resources' => $1, 'num_failures' => $2, 'other_failures' => $3, 'num_updates' => $4}
          found_result_line = true
          break
          if line =~ /Puppet catalog compile failed/
            raise("Could not compile catalog")
          end
        end
      end
      unless puppet_run_type == 'agent'
        raise(Exception, "Did not find result line in file #{puppet_out}") unless found_result_line
      end
      results
    end
  end

  def massage_asm_server_params(serial_number, params)
    if params['rule_number']
      raise(Exception, "Did not expect rule_number in asm::server")
    else
      params['rule_number'] = rule_number
    end

    if params['os_image_type'] == 'vmware_esxi'
      params['broker_type'] = 'noop'
    else
      params['broker_type'] = @puppet_broker
    end

    params['serial_number'] = serial_number
    params['policy_name'] = "policy-#{params['os_host_name']}-#{@id}"

    custom_kickstart_content = (params['custom_script'] || '').strip
    params.delete('custom_script')
    if custom_kickstart_content.length > 0
      custom_script_path = create_custom_script(serial_number,custom_kickstart_content)
      params['custom_script'] = custom_script_path
    end
  end

  def process_compellent()
    log("Processing server component for compellent")

    wwpnSet = Set.new
    if components = @components_by_type['SERVER']
      components.collect do |comp|
        cert_name = comp['id']

        resource_hash = {}
        deviceconf = nil
        inventory = nil
        resource_hash = ASM::Util.build_component_configuration(comp)
        if resource_hash['asm::idrac']
          deviceconf ||= ASM::Util.parse_device_config(cert_name)
          inventory  ||= ASM::Util.fetch_server_inventory(cert_name)
        end

        (resource_hash['asm::server'] || {}).each do |title, params|
          if params['rule_number']
            raise(Exception, "Did not expect rule_number in asm::server")
          else
            params['rule_number'] = rule_number
          end

          # In the case of Dell servers the title should contain
          # the service tag and we retrieve it here
          service_tag = cert_name_to_service_tag(title)
          if service_tag
            params['serial_number'] = service_tag
          else
            params['serial_number'] = title
          end

          params['policy_name'] = "policy-#{params['serial_number']}-#{@id}"

          # TODO: if present this should go in kickstart
          params.delete('custom_script')
        end

        ## get list off WWPN

        (resource_hash['asm::idrac'] || {}).each do |title, params|
          ipaddress = deviceconf[:host]
          username  = deviceconf[:user]
          password  = deviceconf[:password]
          getWWPNData = GetWWPN.new(ipaddress, username, password)
          getWWPNd = getWWPNData.getwwpn
          res = getWWPNd.split(",")
          res.each do |setdata|
            wwpnSet.add(setdata)
          end

        end
      end
    end
    #logger.info("[DEBUG MODE] #{wwpnSet}-------------sanjeev2222222")
    return wwpnSet
  end

  def process_test(component)
    config = ASM::Util.build_component_configuration(component)
    process_generic(component['id'], config, 'apply', true)
  end

  def process_storage(component)
    log("Processing storage component: #{component['id']}")
    config = ASM::Util.build_component_configuration(component)
    process_generic(component['id'], config, 'device')
  end

  def process_tor(component)
    log("Processing tor component: #{component['id']}")
    config = ASM::Util.build_component_configuration(component)
    process_generic(component['id'], config, 'device')
  end

  def configure_tor(server_cert_name)
    device_conf = nil
    inv = nil
    deviceConfDir ='/etc/puppetlabs/puppet/devices'
    $configured_rack_switches.each do |certname|
      conf_file = File.join(deviceConfDir, "#{certname}.conf")
      if !File.exist?(conf_file)
        next
      end
      switchpropertyhash = {}
      switchpropertyhash = Hash.new
      device_conf ||= ASM::Util.parse_device_config(certname)
      logger.debug "******* In process_tor device_conf is #{device_conf} ***********\n"
      torip = device_conf[:host]
      torusername = device_conf[:user]
      torpassword = device_conf['password']
      torurl = device_conf['url']
      logger.debug "****** #{device_conf} ******"
      logger.debug "torip :: #{torip} torusername :: #{torusername} torpassword :: #{torpassword}\n"
      logger.debug "tor url :: #{torurl}\n"
      switchpropertyhash['connection_url'] = torurl
      if certname =~ /dell_ftos/
        switchpropertyhash['device_type'] = "dell_ftos"
      else
        switchpropertyhash['device_type'] = "dell_powerconnect"
      end
      logger.debug "********* switch property hash is #{switchpropertyhash} *************\n"
      $switchhash["#{certname}"] = switchpropertyhash
      logger.debug "********* switch hash is #{$switchhash} *************\n"
    end
    get_server_inventory(server_cert_name)
    logger.debug "******** In process_tor after getServerInventory serverhash is #{$serverhash} **********\n"
    switchinfoobj = Get_switch_information.new($serverhash,$switchhash)
    switchportdetail = switchinfoobj.get_info(logger)
    logger.debug "******** In process_tor switchportdetail :: #{switchportdetail} *********\n"
    tagged_vlaninfo = $server_vlan_info["#{server_cert_name}_taggedvlanlist"]
    tagged_workloadvlaninfo = $server_vlan_info["#{server_cert_name}_taggedworkloadvlanlist"]
    untagged_vlaninfo = $server_vlan_info["#{server_cert_name}_untaggedvlanlist"]
    logger.debug "In configure_tor tagged vlan list found #{tagged_vlaninfo}"
    logger.debug "In configure_tor tagged vlan workload list found #{tagged_workloadvlaninfo}"
    logger.debug "In configure_tor untagged vlan list found #{untagged_vlaninfo}"
    resource_hash = Hash.new
    switchportdetail.each do |switchportdetailhash|
      switchportdetailhash.each do |macaddress,intfhash|
        logger.debug "macaddress :: #{macaddress}    intfhash :: #{intfhash}"
        switchcertname = intfhash[0][0]
        interface = intfhash[0][1][0]
        interfaces = get_interfaces(interface)
        portchannels = get_portchannel(interface)
        logger.debug "switchcertname :: #{switchcertname} interface :: #{interface}"
        tagged_vlaninfo.each do |vlanid|
          logger.debug "vlanid :: #{vlanid}"
          if switchcertname =~ /dell_ftos/
            switch_resource_type = "asm::force10"
            resource_hash[switch_resource_type] = {
              "#{vlanid}" => {
              'vlan_name' => '',
              'desc' => '',
              'tagged_tengigabitethernet' => interfaces.strip,
              'tagged_portchannel' => portchannels.strip,
              'mtu' => 1500,
              }
            }
            logger.debug("*** resource_hash is #{resource_hash} ******")
          elsif switchcertname =~ /dell_powerconnect/
            switch_resource_type = "asm::powerconnect"
            resource_hash[switch_resource_type] = {
              "#{vlanid}" => {
              'vlan_name' => '',
              'portchannel' => portchannels.strip,
              'interface' => interfaces.strip,
              'mode' => 'general'
              }
            }
          elsif switchcertname =~ /dell_iom/
            switch_resource_type = "asm::iom"

          else
            logger.debug "Non-supported switch type"
            return
          end
          process_generic(switchcertname, resource_hash, 'device')
        end
        tagged_workloadvlaninfo.each do |vlanid|
          logger.debug "workload vlanid :: #{vlanid}"
          if switchcertname =~ /dell_ftos/
            switch_resource_type = "asm::force10"
            resource_hash[switch_resource_type] = {
              "#{vlanid}" => {
              'vlan_name' => '',
              'desc' => '',
              'tagged_tengigabitethernet' => interfaces.strip,
              'tagged_portchannel' => portchannels.strip,
              'mtu' => 1500,
              }
            }
            logger.debug("*** resource_hash is #{resource_hash} ******")
          elsif switchcertname =~ /dell_powerconnect/
            switch_resource_type = "asm::powerconnect"
            resource_hash[switch_resource_type] = {
              "#{vlanid}" => {
              'vlan_name' => '',
              'portchannel' => portchannels.strip,
              'interface' => interfaces.strip,
              'mode' => 'general'
              }
            }
          elsif switchcertname =~ /dell_iom/
            switch_resource_type = "asm::iom"

          else
            logger.debug "Non-supported switch type"
            return
          end
          process_generic(switchcertname, resource_hash, 'device')
        end

        untagged_vlaninfo.each do |vlanid|
          logger.debug "vlanid :: #{vlanid}"
          if switchcertname =~ /dell_ftos/
            switch_resource_type = "asm::force10"
            resource_hash[switch_resource_type] = {
              "#{vlanid}" => {
              'vlan_name' => '',
              'desc' => '',
              'untagged_tengigabitethernet' => interfaces.strip,
              'mtu' => 1500,
              }
            }
            logger.debug("*** resource_hash is #{resource_hash} ******")
          elsif switchcertname =~ /dell_iom/
            switch_resource_type = "asm::iom"

          else
            logger.debug "Non-supported switch type"
            return
          end
          process_generic(switchcertname, resource_hash, 'device')
        end
      end
    end

  end

  def configure_tor_blade(server_cert_name)
    device_conf = nil
    inv = nil
    deviceConfDir ='/etc/puppetlabs/puppet/devices'
    $configured_blade_switches.each do |certname|
      conf_file = File.join(deviceConfDir, "#{certname}.conf")
      if !File.exist?(conf_file)
        next
      end
      switchpropertyhash = {}
      switchpropertyhash = Hash.new
      device_conf ||= ASM::Util.parse_device_config(certname)
      puts "******* In process_tor device_conf is #{device_conf} ***********\n"
      torip = device_conf[:host]
      torusername = device_conf[:user]
      torpassword = device_conf['password']
      torurl = device_conf['url']
      logger.debug "****** #{device_conf} ******"
      logger.debug "torip :: #{torip} torusername :: #{torusername} torpassword :: #{torpassword}\n"
      logger.debug "tor url :: #{torurl}\n"
      switchpropertyhash['connection_url'] = torurl
      if certname =~ /dell_iom/
        switchpropertyhash['device_type'] = "dell_iom"
      end
      logger.debug "********* switch property hash is #{switchpropertyhash} *************\n"
      $switchhash["#{certname}"] = switchpropertyhash
      logger.debug "********* switch hash is #{$switchhash} *************\n"
    end
    get_server_inventory(server_cert_name)
    logger.debug "******** In process_tor after getServerInventory serverhash is #{$serverhash} **********\n"
    switchinfoobj = Get_switch_information.new($serverhash,$switchhash)
    switchportdetail = switchinfoobj.get_info(logger)
    logger.debug "******** In process_tor switchportdetail :: #{switchportdetail} *********\n"
    tagged_vlaninfo = $server_vlan_info["#{server_cert_name}_taggedvlanlist"]
    tagged_workloadvlaninfo = $server_vlan_info["#{server_cert_name}_taggedworkloadvlanlist"]
    untagged_vlaninfo = $server_vlan_info["#{server_cert_name}_untaggedvlanlist"]
    logger.debug "In configure_tor tagged vlan list found #{tagged_vlaninfo}"
    logger.debug "In configure_tor tagged vlan workload list found #{tagged_workloadvlaninfo}"
    logger.debug "In configure_tor untagged vlan list found #{untagged_vlaninfo}"
    resource_hash = Hash.new
    switchportdetail.each do |switchportdetailhash|
      switchportdetailhash.each do |macaddress,intfhashes|
        logger.debug "macaddress :: #{macaddress}    intfhash :: #{intfhashes}"

        intfhashes.each do |intfhash|
          switchcertname = intfhash[0]
          interface = intfhash[1][0]
          inv  ||= ASM::Util.fetch_server_inventory(server_cert_name)
          server_service_tag = inv['serviceTag']
          iom_type = ASM::Util.get_iom_type(server_service_tag,switchcertname, logger)
          logger.debug "IOM Type: #{iom_type}"

          logger.debug "switchcertname :: #{switchcertname} interface :: #{interface}"
          logger.debug "Configuring tagged VLANs"

          if iom_type == "ioa"
            if switchcertname =~ /dell_iom/
              switch_resource_type = "asm::ioa"
              resource_hash[switch_resource_type] = {
                "#{interface}" => {
                'vlan_tagged' => tagged_vlaninfo.join(","),
                'vlan_untagged' => untagged_vlaninfo.join(","),
                }
              }
              logger.debug("*** resource_hash is #{resource_hash} ******")
              process_generic(switchcertname, resource_hash, 'device')
            end
          elsif iom_type == "mxl"
            match = interface.match(/(\w*)(\d.*)/)
            interface = $2
            tagged_vlaninfo.each do |vlanid|
              logger.debug "vlanid :: #{vlanid}"
              if switchcertname =~ /dell_iom/
                switch_resource_type = "asm::mxl"
                resource_hash[switch_resource_type] = {
                  "#{vlanid}" => {
                  'vlan_name' => '',
                  'desc' => '',
                  'tagged_tengigabitethernet' => interface,
                  'tagged_portchannel' => '',
                  'mtu' => 2500,
                  }
                }
                logger.debug("*** resource_hash is #{resource_hash} ******")
                process_generic(switchcertname, resource_hash, 'device')
              end
            end # end of tagged vlan loop

            logger.debug "Configuring workload vlans"
            tagged_workloadvlaninfo.each do |vlanid|
              logger.debug "workload vlanid :: #{vlanid}"
              if switchcertname =~ /dell_iom/
                switch_resource_type = "asm::mxl"
                resource_hash[switch_resource_type] = {
                  "#{vlanid}" => {
                  'vlan_name' => '',
                  'desc' => '',
                  'tagged_tengigabitethernet' => interface,
                  'tagged_portchannel' => '',
                  'mtu' => 2500,
                  }
                }
                logger.debug("*** resource_hash is #{resource_hash} ******")
                process_generic(switchcertname, resource_hash, 'device')
              end
            end
            logger.debug "Configuring un-tagged vlans"
            untagged_vlaninfo.each do |vlanid|
              logger.debug "vlanid :: #{vlanid}"
              if switchcertname =~ /dell_iom/
                switch_resource_type = "asm::mxl"
                resource_hash[switch_resource_type] = {
                  "#{vlanid}" => {
                  'vlan_name' => '',
                  'desc' => '',
                  'untagged_tengigabitethernet' => interface,
                  'tagged_portchannel' => '',
                  'mtu' => 2500,
                  }
                }
                logger.debug("*** resource_hash is #{resource_hash} ******")
                process_generic(switchcertname, resource_hash, 'device')
              end

            end

          else
            logger.debug "Non supported IOA type #{iom_type}"
          end

        end

      end
    end

  end

  def get_interfaces(interfaceList)
    logger.debug "Entering get_interfaces #{interfaceList}"
    interfacelist = ""
    interfaceList.split(",").each do |intf|
      if intf =~ /^Te/
        intf = intf.gsub(/Te/, "")
        interfacelist.concat("#{intf} ")
      end
      if intf =~ /^Gi/
        interfacelist.concat("#{intf} ")
      end
    end
    logger.debug "In get_interfaces #{interfacelist}"
    return interfacelist
  end

  def get_portchannel(interfaceList)
    logger.debug "Entering get_portchannel#{interfaceList}"
    portchannellist = ""
    interfaceList.split(",").each do |intf|
      if intf =~ /^\d+/
        portchannellist.concat("#{intf} ")
      end
    end
    return portchannellist
  end

  # If certificate name is of the form bladeserver-SERVICETAG
  # or rackserver-SERVICETAG, return the service tag;
  # otherwise return the certificate name
  def cert_name_to_service_tag(title)
    match = /^(bladeserver|rackserver)-(.*)$/.match(title)
    if match
      match[2].upcase
    else
      nil
    end
  end

  def get_server_inventory(certname)
    serverpropertyhash = {}
    serverpropertyhash = Hash.new
    puts "******** In getServerInventory certname is #{certname} **********\n"
    resourcehash = {}
    device_conf = nil
    inv = nil
    device_conf ||= ASM::Util.parse_device_config(certname)
    inv  ||= ASM::Util.fetch_server_inventory(certname)
    logger.debug "******** In getServerInventory device_conf is #{device_conf}************\n"
    logger.debug "******** In getServerInventory inv is #{inv} **************\n"
    dracipaddress = device_conf[:host]
    dracusername = device_conf[:user]
    dracpassword = device_conf[:password]
    servicetag = inv['serviceTag']
    model = inv['model'].split(' ').last
    logger.debug "dracipaddress :: #{dracipaddress} dracusername :: #{dracusername} dracpassword :: #{dracpassword}\n"
    logger.debug "servicetag :: #{servicetag} model :: #{model}\n"
    if (model =~ /R620/ || model =~ /R720/)
      serverpropertyhash['bladetype'] = "rack"
    else
      serverpropertyhash['bladetype'] = "blade"
      chassis_conf ||= ASM::Util.chassis_inventory(servicetag, logger)
      logger.debug "*********chassis_conf :#{chassis_conf}"
      serverpropertyhash['chassis_ip'] = chassis_conf['chassis_ip']
      serverpropertyhash['chassis_username'] = chassis_conf['chassis_username']
      serverpropertyhash['chassis_password'] = chassis_conf['chassis_password']
      serverpropertyhash['slot_num'] = chassis_conf['slot_num']
      serverpropertyhash['ioaips'] = chassis_conf['ioaips']
    end
    serverpropertyhash['servermodel'] = model
    serverpropertyhash['idrac_ip'] = dracipaddress
    serverpropertyhash['idrac_username'] =  dracusername
    serverpropertyhash['idrac_password'] = dracpassword

    serverpropertyhash['mac_addresses'] = get_server_macaddress(dracipaddress,dracusername,dracpassword,certname)
    logger.debug "******* In getServerInventory server property hash is #{serverpropertyhash} ***********\n"
    $serverhash["#{servicetag}"] = serverpropertyhash
    logger.debug "********* In getServerInventory server Hash is #{$serverhash} **************\n"
    return $serverhash
  end

  def get_all_switches()
    #$configured_rack_switches = get_all_rack_switches()
    #$configured_blade_switches = get_all_blade_switches()
    #switchList = Array.new
    puppet_out = File.join(deployment_dir, "puppetcert.out")
    cmd = "sudo puppet cert list --all"
    if File.exists?(puppet_out)
      File.delete(puppet_out)
    end

    ASM::Util.run_command(cmd, puppet_out)
    resp = File.read(puppet_out)
    resp.split("\n").each do |line|
      if line =~ /dell_ftos/
        logger.debug "Found dell ftos certificate"
        res = line.to_s.strip.split(' ')
        switchCert = res[1]
        switchCert = switchCert.gsub(/\"/, "")
        puts "FTOS switch certificate is #{switchCert}"
        $configured_rack_switches.push(switchCert)
      end
      if line =~ /dell_powerconnect/
        logger.debug "Found dell powerconnect certificate"
        res = line.to_s.strip.split(' ')
        switchCert = res[1]
        switchCert = switchCert.gsub(/\"/, "")
        puts "Powerconnect switch certificate is #{switchCert}"
        $configured_rack_switches.push(switchCert)
      end
      if line =~ /dell_iom/
        logger.debug "Found dell powerconnect certificate"
        res = line.to_s.strip.split(' ')
        switchCert = res[1]
        switchCert = switchCert.gsub(/\"/, "")
        puts "Powerconnect switch certificate is #{switchCert}"
        $configured_blade_switches.push(switchCert)
      end
    end
    logger.debug "Rack ToR Switch certificate name list is #{$configured_rack_switches}"
    logger.debug "Blade IOM Switch certificate name list is #{$configured_blade_switches}"
    #return switchList
  end

  #  def get_all_blade_switches()
  #    switchList = Array.new
  #    cmd = "sudo puppet cert list --all"
  #    puppet_out = File.join(deployment_dir, "puppetcert.out")
  #    ASM::Util.run_command(cmd, puppet_out)
  #    resp = File.read(puppet_out)
  #    resp.split("\n").each do |line|
  #      if line =~ /dell_iom/
  #        logger.debug "Found dell iom certificate"
  #        res = line.to_s.strip.split(' ')
  #        switchCert = res[1]
  #        switchCert = switchCert.gsub(/\"/, "")
  #        logger.debug "Dell IOM switch certificate is #{switchCert}"
  #        switchList.push(switchCert)
  #      end
  #    end
  #    logger.debug "Switch certificate name list is #{switchList}"
  #    return switchList
  #  end

  def get_server_macaddress(dracipaddress,dracusername,dracpassword,certname)
    macAddressList = Array.new
    cmd = "wsman enumerate http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_NICView -h  #{dracipaddress}  -V -v -c dummy.cert -P 443 -u #{dracusername} -p #{dracpassword} -j utf-8 -y basic"
    puppet_out = File.join(deployment_dir, "servermac.out")
    ASM::Util.run_command(cmd, puppet_out)
    resp = File.read(puppet_out)
    if certname =~ /rackserver/
      macAddress = ""
      resp.split("\n").each do |line|
        line = line.to_s
        if line =~ /\<n1:CurrentMACAddress\>(\S+)\<\/n1:CurrentMACAddress\>/
          macAddress = $1
        end
        if line =~ /\<n1:FQDD\>(\S+)\<\/n1:FQDD\>/
          nicName = $1
          if (nicName == "NIC.Slot.2-1-1" || nicName == "NIC.Slot.2-2-1")
            macAddressList.push(macAddress)
          end
        end
      end
    else
      macAddress = ""
      resp.split("\n").each do |line|
        line = line.to_s
        if line =~ /\<n1:CurrentMACAddress\>(\S+)\<\/n1:CurrentMACAddress\>/
          macAddress = $1
        end
        if line =~ /\<n1:FQDD\>(\S+)\<\/n1:FQDD\>/
          nicName = $1
          if (nicName == "NIC.Integrated.1-1-1" || nicName == "NIC.Integrated.1-2-1")
            macAddressList.push(macAddress)
          end
        end
      end
    end
    logger.debug "********* MAC Address List is #{macAddressList} **************\n"
    return macAddressList
  end

  def process_server(component)
    log("Processing server component: #{component['id']}")
    cert_name = component['id']

    # In the case of Dell servers the cert_name should contain
    # the service tag and we retrieve it here
    serial_number = cert_name_to_service_tag(cert_name) || cert_name

    resource_hash = {}
    deviceconf = nil
    inventory = nil
    resource_hash = ASM::Util.build_component_configuration(component)
    if resource_hash['asm::idrac']
      deviceconf ||= ASM::Util.parse_device_config(cert_name)
      inventory  ||= ASM::Util.fetch_server_inventory(cert_name)
    end

    if inventory
      # Putting the re-direction as per the blade type
      # Blade and RACK server
      get_server_networks(component,cert_name)
      blade_type = inventory['serverType'].downcase
      logger.debug("Server Blade type: #{blade_type}")
      if blade_type == "rack"
        logger.debug "Configuring rack server"
        if $configured_rack_switches.length() > 0
          logger.debug "Configuring ToR configuration for server #{cert_name}"
          configure_tor(cert_name)
        else
          logger.debug "INFO: There are no RACK ToR Switches in the ASM Inventory"
        end
      else
        if $configured_blade_switches.length() > 0
          logger.debug "Configuring blade server"
          configure_tor_blade(cert_name)
        else
          logger.debug "INFO: There are no IOM Switches in the ASM Inventory"
        end
      end
    end

    (resource_hash['asm::server'] || {}).each do |title, params|
      massage_asm_server_params(serial_number, params)
    end

    (resource_hash['asm::idrac'] || {}).each do |title, params|
      # Attempt to determine this machine's IP address, which
      # should also be the NFS server. This is error-prone
      # and should be fixed later.
      params['nfsipaddress'] = ASM::Util.first_host_ip
      params['nfssharepath'] = '/var/nfs/idrac_config_xml'
      params['nfslocaldir'] = '/var/nfs/idrac_config_xml'
      params['dracipaddress'] = deviceconf[:host]
      params['dracusername'] = deviceconf[:user]
      params['dracpassword'] = deviceconf[:password]
      params['servicetag'] = inventory['serviceTag']
      params['model'] = inventory['model'].split(' ').last.downcase

      if resource_hash['asm::server']
        params['before'] = "Asm::Server[#{title}]"
      end

    end

    # Network settings (vswitch config) is done in cluster swim lane
    resource_hash.delete('asm::esxiscsiconfig')

    skip_deployment = nil
    begin
      node = (find_node(serial_number) || {})
      if node['policy'] && node['policy']['name']
        policy = get('policies', node['policy']['name'])
        razor_params = resource_hash['asm::server'][cert_name]
        if policy &&
        (policy['repo'] || {})['name'] == razor_params['razor_image'] &&
        (policy['installer'] || {})['name'] == razor_params['os_image_type']
          skip_deployment = true
        end
      end
    rescue Timeout::Error
      skip_deployment = nil
    end

    if skip_deployment
      # In theory the puppet razor and idrac modules should be idempotent
      # and we could call process_generic without affecting them if they
      # are already in the desired state. However, the idrec module
      # currently always reboots the server
      log("Skipping deployment of #{cert_name}; already complete.")
    else
      process_generic(component['id'], resource_hash, 'apply', 'true')
      unless @debug
        (resource_hash['asm::server'] || []).each do |title, params|
          block_until_server_ready(title, params, timeout=3600)
        end
      end
    end
  end

  #
  # Razor requires unique rule numbers per deployment that set priority.
  # This routine is able to safely generate 100 per second.
  #
  def rule_number
    currtime = Integer(Time.now.strftime("%s"))
    # Using the unix epoch time times 100 is too big for razor's
    # rule_number, it must fit in signed int. So we subtract off
    # the time at Jan 1, 2014
    offset = 1388534400 # time at Jan 1, 2014
    ((currtime - offset) * 100) + (ASM.counter % 100)
  end

  # Find components of the given type which are related to component
  def find_related_components(type, component)
    all = (@components_by_type[type] || [])
    relatedComponents = component['relatedComponents']
    if !relatedComponents || (relatedComponents.is_a?(String) && relatedComponents.empty?)
      related = []
    else
      related = ASM::Util.asm_json_array(relatedComponents['entry'])
    end
    related_ids = related.map { |elem|  elem['key'] }
    all.select { |component| related_ids.include?(component['id']) }
  end

  def build_portgroup(vswitch, path, hostip, portgroup_name, network,
    portgrouptype, active_nics)
    ret = {
      'name' => "#{hostip}:#{portgroup_name}",
      'ensure' => 'present',
      'portgrouptype' => portgrouptype,
      'overridefailoverorder' => 'disabled',
      'failback' => true,
      'mtu' => 9000,
      'overridefailoverorder' => 'enabled',
      'nicorderpolicy' => {
      # TODO: for iSCSI they cannot both be active
      'activenic' => active_nics,
      'standbynic' => [],
      },
      'overridecheckbeacon' => 'enabled',
      'checkbeacon' => true,
      'traffic_shaping_policy' => 'disabled',
      'averagebandwidth' => 1000,
      'peakbandwidth' => 1000,
      'burstsize' => 1024,
      'vswitch' => vswitch,
      'path' => path,
      'host' => hostip,
      'vlanid' => network['vlanId'],
      'transport' => 'Transport[vcenter]',
    }
  end

  def build_vswitch(server_cert, index, network_guids, hostip,
    params, server_params)
    vswitch_name = "vSwitch#{index}"
    vmnic1 = "vmnic#{index * 2}"
    vmnic2 = "vmnic#{(index * 2) + 1}"
    path = "/#{params['datacenter']}/#{params['cluster']}"

    nics = [ vmnic1, vmnic2 ]
    ret = { 'esx_vswitch' => {}, 'esx_portgroup' => {}, }
    vswitch_title = "#{hostip}:#{vswitch_name}"
    ret['esx_vswitch'][vswitch_title] = {
      'ensure' => 'present',
      'num_ports' => 1024,
      'nics' => [ vmnic1, vmnic2 ],
      'nicorderpolicy' => {
      'activenic' => nics,
      'standbynic' => [],
      },
      'path' => path,
      'mtu' => 9000,
      'checkbeacon' => true,
      'transport' => 'Transport[vcenter]',
    }

    portgrouptype = 'VMkernel'
    next_require = "Esx_vswitch[#{hostip}:#{vswitch_name}]"

    networks = network_guids.map do |guid|
      ASM::Util.fetch_network_settings(guid)
    end
    portgroup_names = nil
    if index == 3
      # iSCSI network
      # NOTE: We have to make sure the ISCSI1 requires ISCSI0 so that
      # they are created in the "right" order -- the order that will
      # give ISCSI0 vmk2 and ISCSI1 vmk3 vmknics. The datastore
      # configuration relies on that.
      portgroup_names = [ 'ISCSI0', 'ISCSI1' ]
      raise(Exception, "Only one network expected for storage network") unless networks.size ==1
      networks = [ networks[0], networks[0] ]
    else
      if index == 2
        portgrouptype = 'VirtualMachine'
      end
      portgroup_names = networks.map { |network| network['name'] }
    end

    portgroup_names.each_with_index do |portgroup_name, index|
      network = networks[index]
      portgroup_title = "#{hostip}:#{portgroup_name}"
      portgroup = build_portgroup(vswitch_name, path, hostip, portgroup_name,
      network, portgrouptype, [ nics[index] ])

      static = network['staticNetworkConfiguration']

      if static
        # TODO: we should consolidate our reservation requests
        reservation_guid = "#{@id}-#{portgroup_title}"
        ip = ASM::Util.reserve_network_ips(network['id'],
        portgroup_names.size,
        reservation_guid)[0]
        raise(Exception, "Subnet not found in configuration #{static.inspect}") unless static['subnet']

        portgroup['ipsettings'] = 'static'
        portgroup['ipaddress'] = ip
        portgroup['subnetmask'] = static['subnet']
      else
        portgroup['ipsettings'] = 'dhcp'
        portgroup['ipaddress'] = ''
        portgroup['subnetmask'] = ''
      end

      portgroup['require'] = next_require
      ret['esx_portgroup'][portgroup_title] = portgroup
      next_require = "Esx_portgroup[#{portgroup_title}]"
    end

    ret
  end

  def process_cluster(component)
    cert_name = component['id']
    raise(Exception, 'Component has no certname') unless cert_name
    log("Processing cluster component: #{cert_name}")

    resource_hash = ASM::Util.build_component_configuration(component)

    # Add vcenter creds to asm::cluster resources
    deviceconf = ASM::Util.parse_device_config(cert_name)
    resource_hash['asm::cluster'].each do |title, params|
      resource_hash['asm::cluster'][title]['vcenter_server'] = deviceconf[:host]
      resource_hash['asm::cluster'][title]['vcenter_username'] = deviceconf[:user]
      resource_hash['asm::cluster'][title]['vcenter_password'] = deviceconf[:password]
      resource_hash['asm::cluster'][title]['vcenter_options'] = { 'insecure' => true }
      resource_hash['asm::cluster'][title]['ensure'] = 'present'

      # Add ESXi hosts and creds as separte resources
      (find_related_components('SERVER', component) || []).each do |server_component|
        server_conf = ASM::Util.build_component_configuration(server_component)

        (server_conf['asm::server'] || []).each do |server_cert, server_params|
          if server_params['os_image_type'] == 'vmware_esxi'
            serial_number = cert_name_to_service_tag(server_cert)
            unless serial_number
              serial_number = server_cert
            end

            log("Finding host ip for serial number #{serial_number}")
            hostip = find_host_ip(serial_number)
            if @debug && !hostip
              hostip = "DEBUG-IP-ADDRESS"
            end
            raise(Exception, "Could not find host ip for #{server_cert}") unless hostip
            serverdeviceconf = ASM::Util.parse_device_config(server_cert)

            # Add esx hosts to cluster
            resource_hash['asm::host'] ||= {}
            resource_hash['asm::host'][server_cert] = {
              'datacenter' => params['datacenter'],
              'cluster' => params['cluster'],
              'hostname' => hostip,
              'username' => 'root',
              'password' => server_params['admin_password'],
              'require' => "Asm::Cluster[#{title}]"
            }

            network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
            @logger.debug("network_params = #{network_params.to_yaml}")
            if network_params
              # Add vswitch config to esx host
              resource_hash['asm::vswitch'] ||= {}

              next_require = "Asm::Host[#{server_cert}]"
              storage_network_require = nil
              storage_network_vmk_index = nil
              vmk_index = 0
              [ 'hypervisor_network', 'vmotion_network', 'workload_network', 'storage_network' ].each_with_index do | type, index |
                guid = network_params[type]
                if !empty_guid?(guid)
                  # For workload, guid may be a comma-separated list
                  log("Configuring #{type} = #{guid}")
                  guids = guid.split(',').select { |x| !x.empty? }
                  vswitch_resources = build_vswitch(server_cert, index,
                  guids, hostip,
                  params, server_params)
                  # Should be exactly one vswitch in response
                  vswitch_title = vswitch_resources['esx_vswitch'].keys[0]
                  vswitch = vswitch_resources['esx_vswitch'][vswitch_title]
                  vswitch['require'] = next_require

                  # Set next require to this vswitch so they are all
                  # ordered properly
                  next_require = "Esx_vswitch[#{vswitch_title}]"
                  if type == 'storage_network'
                    storage_network_require = []
                    storage_network_vmk_index = vmk_index
                    vswitch_resources['esx_portgroup'].each do |portgroupname, portgroupparams|
                      storage_network_require.push("Esx_portgroup[#{portgroupname}]")
                    end
                  end

                  vswitch_resources['esx_portgroup'].each do |title, portgroup|
                    if portgroup['portgrouptype'] == 'VMkernel'
                      vmk_index += 1
                    end
                  end

                  if type == 'hypervisor_network' && vmk_index < 1
                    # Even if we don't create a vmk for hypervisor_network
                    # one will have been automatically created
                    vmk_index = 1
                  end

                  log("Built vswitch resources = #{vswitch_resources.to_yaml}")

                  # merge these in
                  resource_hash['esx_vswitch'] = (resource_hash['esx_vswitch'] || {}).merge(vswitch_resources['esx_vswitch'])
                  resource_hash['esx_portgroup'] = (resource_hash['esx_portgroup'] || {}).merge(vswitch_resources['esx_portgroup'])
                end
              end

              # Connect datastore if we have both storage and a storage network
              if storage_network_require
                (find_related_components('STORAGE', server_component) || []).each do |storage_component|
                  storage_cert = storage_component['id']
                  storage_creds = ASM::Util.parse_device_config(storage_cert)
                  storage_hash = ASM::Util.build_component_configuration(storage_component)
                  (storage_hash['equallogic::create_vol_chap_user_access'] || {}).each do |storage_title, storage_params|
                    resource_hash['asm::datastore'] = (resource_hash['asm::datastore'] || {})
                    resource_hash['asm::datastore']["#{hostip}:#{storage_title}"] = {
                      'data_center' => params['datacenter'],
                      'datastore' => params['datastore'],
                      'cluster' => params['cluster'],
                      'ensure' => 'present',
                      'esxhost' => hostip,
                      'esxusername' => 'root',
                      'esxpassword' => server_params['admin_password'],
                      'iscsi_target_ip' => ASM::Util.find_equallogic_iscsi_ip(storage_cert),
                      'chapname' => storage_params['chap_user_name'],
                      'chapsecret' => storage_params['passwd'],
                      'vmknics' => "vmk#{storage_network_vmk_index}",
                      'vmknics1' => "vmk#{storage_network_vmk_index + 1}",
                      'require' => storage_network_require,
                    }
                  end
                end
              end

            end
          end
        end
      end
    end
    process_generic(cert_name, resource_hash, 'apply')
    # Running into issues with hosts not coming out of maint mode
    # Try it again for good measure.
    process_generic(cert_name, resource_hash, 'apply')
  end

  def process_virtualmachine(component)
    log("Processing virtualmachine component: #{component['id']}")
    resource_hash = ASM::Util.build_component_configuration(component)

    # For simplicity we require that there is exactly one asm::vm
    # and optionally one asm::server resource
    unless resource_hash['asm::vm'] && resource_hash['asm::vm'].size == 1
      raise(Exception, "Exactly one set of VM configuration parameters is required")
    end
    vm_params = resource_hash['asm::vm'][resource_hash['asm::vm'].keys[0]]

    if resource_hash['asm::server'] && resource_hash['asm::server'].size > 1
      raise(Exception, "One or no sets of VM O/S configuration parameters required but #{resource_hash['asm::server'].size} were passed")
    end

    unless resource_hash['asm::server']
      server_params = nil
    else
      server_params = resource_hash['asm::server'][resource_hash['asm::server'].keys[0]]
    end

    clusters = (find_related_components('CLUSTER', component) || [])
    raise(Exception, "Expected one cluster for #{component['id']} but found #{clusters.size}") unless clusters.size == 1
    cluster = clusters[0]
    cluster_deviceconf = ASM::Util.parse_device_config(cluster['id'])
    cluster_resource_hash = ASM::Util.build_component_configuration(cluster)
    cluster_hash = cluster_resource_hash['asm::cluster'] || {}
    raise(Exception, "Expected one asm::cluster resource but found #{cluster_hash.size}") unless cluster_hash.size == 1
    cluster_params = nil
    cluster_hash.each do |title, params|
      cluster_params ||= params
    end

    vm_params['hostname'] = (server_params || {})['os_host_name']
    hostname = vm_params['hostname'] || raise(Exception, "VM host name not specified")
    if server_params['os_image_type'] == 'windows'
      vm_params['os_type'] = 'windows'
    else
      vm_params['os_type'] = 'linux'
    end
    
    vm_params['vcenter_username'] = cluster_deviceconf[:user]
    vm_params['vcenter_password'] = cluster_deviceconf[:password]
    vm_params['vcenter_server'] = cluster_deviceconf[:host]
    vm_params['vcenter_options'] = { 'insecure' => true }
    vm_params['ensure'] = 'present'

    # Set titles from the host name. Can't be easily done from the
    # front-end because the host name is only entered in the
    # asm::server section
    resource_hash = { 'asm::vm' => { hostname => vm_params }}

    log("Creating VM #{hostname}")
    vm_cert_name = "vm-#{hostname.downcase}" # cert names must be lower-case
    process_generic(vm_cert_name, resource_hash, 'apply')

    # TODO: Puppet module does not power it on first time.
    log("Powering on #{hostname}")
    process_generic(vm_cert_name, resource_hash, 'apply')

    if server_params
      uuid = nil
      begin
        uuid = ASM::Util.find_vm_uuid(cluster_deviceconf, hostname)
      rescue Exception => e
        if @debug
          puts e
          uuid = "DEBUG-MODE-UUID"
        else
          raise e
        end
      end
      log("Found UUID #{uuid} for #{hostname}")
      log("Initiating O/S install for VM #{hostname}")
      server_cert_name = "server-#{hostname}"

      # Work around incorrect name in GUI for now
      # TODO: remove when no longer needed
      old_image_param = server_params.delete('os_type')
      if old_image_param
        @logger.warn('Incorrect os image param name os_type')
        server_params['os_image_type'] = old_image_param
      end

      serial_number = @debug ? "vmware_debug_serial_no" : ASM::Util.vm_uuid_to_serial_number(uuid)
      massage_asm_server_params(serial_number, server_params)

      resource_hash = { 'asm::server' => { hostname => server_params } }
      process_generic(server_cert_name, resource_hash, 'apply')
    end
  end

  def process_service(component)
    log("Processing service component: #{component['id']}")
    config = ASM::Util.build_component_configuration(component)
    process_generic(component['id'], config, 'apply')
  end

  def find_node(serial_num)
    ret = nil
    results = get('nodes').each do |node|
      results = get('nodes', node['name'])
      # Facts will be empty for a period until server checks in
      serial  = (results['facts'] || {})['serialnumber']
      if serial == serial_num
        ret = results
      end
    end
    ret
  end

  def find_host_ip(serial_num)
    node = find_node(serial_num)
    if node && node['facts'] && node['facts']['ipaddress']
      node['facts']['ipaddress']
    else
      nil
    end
  end

  def find_host_ip_blocking(serial_num, timeout)
    ipaddress = nil
    max_sleep = 30
    ASM::Util.block_and_retry_until_ready(timeout, CommandException, max_sleep) do
      ipaddress = find_host_ip(serial_num)
      unless ipaddress
        raise(CommandException, "Did not find our node by its serial number. Will try again")
      end
    end
    ipaddress
  end

  # converts from an ASM style server resource into
  # a method call to check if the esx host is up
  def block_until_server_ready(title, params, timeout=3600)
    serial_num = params['serial_number'] || raise(Exception, "resource #{title} is missing required server attribute admin_password")
    password = params['admin_password'] || raise(Exception, "resource #{title} is missing required server attribute admin_password")
    type = params['os_image_type'] || raise(Exception, "resource #{title} is missing required server attribute os_image_type")
    hostname = params['os_host_name'] || raise(Exception, "resource #{title} is missing required server attribute os_host_name")

    if type == 'vmware_esxi'
      log("Waiting until #{hostname} has checked in with Razor")
      ip_address = find_host_ip_blocking(serial_num, timeout)
      log("#{hostname} has checked in with Razor with ip address #{ip_address}")

      log("Waiting until #{hostname} (#{serial_num}) is ready")
      ASM::Util.block_and_retry_until_ready(timeout, CommandException, 150) do
        esx_command =  "system uuid get"
        cmd = "esxcli --server=#{ip_address} --username=root --password=#{password} #{esx_command}"
        log("Checking for system uuid on #{ip_address}")
        results = ASM::Util.run_command_simple(cmd)
        unless results['exit_status'] == 0 and results['stdout'] =~ /[1-9a-z-]+/
          raise(CommandException, results['stderr'])
        end
      end
    else
      logger.warn("Do not know how to block for servers of type #{type}")
    end
    log("Server #{hostname} is available")
  end

  private

  def deployment_dir
    @deployment_dir ||= begin
      deployment_dir = File.join(ASM.base_dir, @id.to_s)
      if File.exists?(deployment_dir)
        ASM.logger.warn("Service profile for #{@id} already exists")
      else
        FileUtils.mkdir_p(deployment_dir)
      end
      @deployment_dir = deployment_dir
    end
  end

  def resources_dir
    dir = File.join(deployment_dir, "resources")
    FileUtils.mkdir_p(dir)
    dir
  end

  def create_logger
    id_log_file = File.join(deployment_dir, "deployment.log")
    File.open(id_log_file, 'w')
    Logger.new(id_log_file)
  end

  def create_custom_script(cert_name,file_content)
    id_log_file = File.join(deployment_dir, "#{cert_name}.cfg")
    File.open(id_log_file, 'w') do |filehandle|
      filehandle.puts file_content
    end
    id_log_file.to_s
  end

  def get(type, name=nil)
    begin
      response = nil
      if name
        response = RestClient.get(
        "http://localhost:8080/api/collections/#{type}/#{name}"
        )
      else
        response = RestClient.get(
        "http://localhost:8080/api/collections/#{type}"
        )
      end
    rescue RestClient::ResourceNotFound => e
      raise(CommandException, "rest call failed #{e}")
    end
    if response.code == 200
      JSON.parse(response)
    else
      raise(CommandException, "bad http code: #{response.code}:#{response.to_str}")
    end
  end

  def empty_guid?(guid)
    !guid || guid.to_s.empty? || guid.to_s == '-1'
  end

  def get_server_networks(server_component,server_cert)
    hypervisormanagementvlanid = ""
    vmotionvlanid = ""
    iscsivlanid = ""
    pxevlanid = ""
    workloadvlanid = ""
    tagged_vlaninfo = Array.new
    tagged_workloadvlaninfo = Array.new
    untagged_vlaninfo = Array.new
    server_conf = ASM::Util.build_component_configuration(server_component)
    network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
    if network_params
      hypervisormanagementguid = network_params["hypervisor_network"]
      logger.debug "hypervisormanagementguid :: #{hypervisormanagementguid}"
      if !empty_guid?(hypervisormanagementguid)
        network = ASM::Util.fetch_network_settings(hypervisormanagementguid)
        logger.debug "network :: #{network}"
        hypervisormanagementvlanid = network['vlanId']
      end
      vmotionguid = network_params["vmotion_network"]
      if !empty_guid?(vmotionguid)
        network = ASM::Util.fetch_network_settings(vmotionguid)
        vmotionvlanid = network['vlanId']
      end
      logger.debug "Vmotion GUID: #{vmotionguid}"
      iscsiguid = network_params["storage_network"]
      if !empty_guid?(iscsiguid)
        network = ASM::Util.fetch_network_settings(iscsiguid)
        iscsivlanid = network['vlanId']
      end
      logger.debug "iSCSI GUID  #{iscsiguid}"
      workloadguids = network_params["workload_network"]
      workloadguids = empty_guid?(workloadguids) ? [] : workloadguids.split(",")
      workloadguids.each do |workloadguid|
        workloadguid = workloadguid.strip
        if !empty_guid?(workloadguid)
          network = ASM::Util.fetch_network_settings(workloadguid)
          tagged_workloadvlaninfo.push(network['vlanId'])
        end
      end
      pxeguid = network_params["pxe_network"]
      if !empty_guid?(pxeguid)
        network = ASM::Util.fetch_network_settings(pxeguid)
        pxevlanid = network['vlanId']
      end
      logger.debug "pxeguid: #{pxeguid}"
      logger.debug "hypervisormanagementvlanid :: #{hypervisormanagementvlanid} vmotionvlanid :: #{vmotionvlanid} iscsivlanid :: #{iscsivlanid} workloadvlanids :: #{tagged_workloadvlaninfo} pxevlanid :: #{pxevlanid}"

      if hypervisormanagementvlanid != ""
        tagged_vlaninfo.push(hypervisormanagementvlanid.to_s)
      end

      if vmotionvlanid != ""
        tagged_vlaninfo.push(vmotionvlanid.to_s)
      end

      if iscsivlanid != ""
        tagged_vlaninfo.push(iscsivlanid.to_s)
      end

      if pxevlanid != ""
        untagged_vlaninfo.push(pxevlanid.to_s)
      end

      logger.debug "Tagged vlan info #{tagged_vlaninfo}"
      logger.debug "Untagged vlan info #{untagged_vlaninfo}"
      $server_vlan_info["#{server_cert}_taggedvlanlist"] = tagged_vlaninfo
      $server_vlan_info["#{server_cert}_taggedworkloadvlanlist"] = tagged_workloadvlaninfo
      $server_vlan_info["#{server_cert}_untaggedvlanlist"] = untagged_vlaninfo
      puts "Server vlan hash is #{$server_vlan_info}"
    end
    return $server_vlan_info
  end

  def create_broker_if_needed()
    hostip = ASM::Util.first_host_ip
    broker_name = "puppet-#{hostip}"
    found_broker = nil
    results = get('brokers').each do |node|
      if node['name'] == broker_name
        found_broker = true
      end
    end

    unless found_broker
      response = nil
      broker = {
        'name' => broker_name,
        'configuration' => { 'server' => hostip, },
        'broker-type' => 'puppet',
      }
      url = 'http://localhost:8080/api/commands/create-broker'
      begin
        response = RestClient.post(url, broker.to_json,
        :content_type => :json,
        :accept => :json)
      rescue RestClient::ResourceNotFound => e
        raise(CommandException, "rest call failed #{e}")
      end
      if response.code == 200 || response.code == 202
        JSON.parse(response)
      else
        raise(CommandException, "bad http code: #{response.code}:#{response.to_str}")
      end
    end
    broker_name
  end

end
