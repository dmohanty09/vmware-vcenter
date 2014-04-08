require 'asm'
require 'asm/util'
require 'asm/processor/server'
require 'fileutils'
require 'json'
require 'logger'
require 'open3'
require 'rest_client'
require 'timeout'
require 'securerandom'
require 'yaml'
require 'asm/wsman'
require 'fileutils'
require 'asm/get_switch_information'
require 'uri'
require 'asm/discoverswitch'
require 'asm/cipher'

class ASM::ServiceDeployment

  ESXI_ADMIN_USER = 'root'

  class CommandException < Exception; end

  class SyncException < Exception; end

  class PuppetEventException < Exception; end

  def initialize(id)
    unless id
      raise(Exception, "Service deployment must have an id")
    end
    @id = id
    @configured_rack_switches = Array.new
    @configured_blade_switches = Array.new
    @configured_brocade_san_switches = Array.new
    @rack_server_switchhash = {}
    @blade_server_switchhash = {}
    @brocade_san_switchhash = {}
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

  def noop=(noop)
    @noop = noop
  end

  def decrypt?
    true
  end

  # Network values come from the GUI as a list of ASM network guids.
  # Those must be looked up from an ASM REST service, and if they
  # correspond to a static network, static IPs must be reserved from
  # the ASM REST service.
  #
  # This method replaces the parameter's list of guids with the
  # corresponding list of ASM networks. For static IPs, those networks
  # will have an additional field added corresponding to the IP to use:
  # parameter['value']['staticNetworkConfiguration']['ip_address']
  #
  # Doing this lookup and reservation in advance of processing the
  # components is done for two reasons:
  #
  # 1. The deployment will fail immediately if there are not enough
  #    static IP addresses available to fulfill the deployment.
  #
  # 2. All reserved IP addresses will be tied to the same "usage id",
  #    which will be the deployment id. This allows all of the static
  #    IPs associated with a deployment to be relased by calling the
  #    reservation service with the deployment id.
  def massage_networks!(server_components)
    guid_to_params = {}

    # Build guid_to_params map of network guid to list of matching parameters
    networks = [ 'hypervisor_network', 'converged_network', 'vmotion_network',
                 'workload_network', 'storage_network', 'pxe_network',
                 'private_cluster_network', 'live_migration_network' ]
    server_components.each do |component|
      resources = ASM::Util.asm_json_array(component['resources']) || []
      resources.each do |resource|
        parameters = ASM::Util.asm_json_array(resource['parameters']) || []
        parameters.each do |param|
          if networks.include?(param['id'])
            if !empty_guid?(param['value'])
              # value may be a comma-separated list, but if that is the
              # case it will lead with a comma, e.g. ,1,2,3
              # The reject below gets rid of the initial empty element
              guids = param['value'].split(',').reject { |x| x.empty? }

              # Storage network special case: two portgroups are always
              # created, so we need two networks, but only one is passed in
              if param['id'] == 'storage_network' && guids.size == 1
                guids.push(guids[0])
              end


              guids.each do |guid|
                guid_to_params[guid] ||= []
                guid_to_params[guid].push(param)
              end
            end

            # Overwrite value with nil, later we will add the value
            param['value'] = nil
          end
        end
      end
    end

    # Look up each network guid
    guid_to_network = {}
    guid_to_params.each do |guid, params|
      network = ASM::Util.fetch_network_settings(guid)
      guid_to_network[guid] = network
    end

    # By default our ESXi hosts boot with 'VM Network' and 'Management
    # Network' names. To avoid having new networks conflict with
    # those, replace those names with non-conflicting ones.
    reserved_names = [ 'VM Network', 'Management Network' ]
    all_names = guid_to_network.values.map { |network| network['name'] }
    guid_to_network.each do |guid, network|
      name = network['name']
      if reserved_names.include?(name)
        i = 1
        begin
          replacement = "#{name} (#{i})"
          i += 1
        end while all_names.include?(replacement)
        network['name'] = replacement
      end
    end

    # Do static IP reservations if necessary and update params
    guid_to_params.each do |guid, params|
      network = guid_to_network[guid]
      n_ips = params.size
      ips = nil
      if network['staticNetworkConfiguration']
        ips = ASM::Util.reserve_network_ips(network['id'], n_ips, @id)
      else
        ips = Array.new(n_ips) # empty array, won't be used
      end

      # Add a copy of the network to param['value']
      params.each_with_index do |param, index|
        value = network.dup
        if value['staticNetworkConfiguration']
          # WARNING: dup doesn't dup the values! staticNetworkConfiguration
          # is a hash, so we have to dup it again to maintain separate objects
          value['staticNetworkConfiguration'] = network['staticNetworkConfiguration'].dup
          value['staticNetworkConfiguration']['ip_address'] = ips[index]
        elsif param['id'] == 'hypervisor_network'
          msg = "Static networks are required for the hypervisor network and #{network['name']} is DHCP."
          logger.error(msg)
          raise(Exception, msg)
        end

        param['value'] ||= []
        param['value'].push(value)
      end
    end

  end

  def process(service_deployment)
    begin
      ASM.logger.info("Deploying #{service_deployment['deploymentName']} with id #{service_deployment['id']}")
      log("Status: Started")
      log("Starting deployment #{service_deployment['deploymentName']}")

      # Write the deployment to filesystem for ease of debugging / reuse
      File.open(File.join(deployment_dir, 'deployment.json'), 'w') do |file|
        file.write(JSON.pretty_generate({ "Deployment" => service_deployment }))
      end

      hostlist = ASM::DeploymentTeardown.get_deployment_certs(service_deployment)
      dup_servers = hostlist.select{|element| hostlist.count(element) > 1 }
      unless dup_servers.empty?
        msg = "Duplicate host names found in deployment #{dup_servers.inspect}"
        logger.error(msg)
        raise(Exception, msg)
      end

      ds = ASM::Util.check_host_list_against_previous_deployments(hostlist)
      unless ds.empty?
        msg = "The listed hosts are already in use #{ds.inspect}"
        logger.error(msg)
        raise(Exception, msg)
      end

      # Will need to access other component types during deployment
      # of a given component type in the future, e.g. VSwitch configuration
      # information is contained in the server component type data
      @components_by_type = components_by_type(service_deployment)
      massage_networks!(@components_by_type['SERVER'] || [])
      get_all_switches()
      @rack_server_switchhash = self.populate_rack_switch_hash()
      @blade_server_switchhash = self.populate_blade_switch_hash()
      @brocade_san_switchhash = self.populate_brocade_san_switch_hash()
      # Changing the ordering of SAN and LAN configuration
      # To ensure that the server boots with razor image
      process_tor_switches()
      process_san_switches()
      process_components()
    rescue Exception => e
      File.open(File.join(deployment_dir, "exception.log"), 'w') do |fh|
        fh.puts(e.inspect)
        fh.puts
        (e.backtrace || []).each { |line| fh.puts(line) }
      end
      log("Status: Error")
      raise(e)
    ensure
      update_vcenters
    end
    log("Status: Completed")
  end

  def process_tor_switches()
    # Get all Servers
    (@components_by_type['SERVER'] || []).each do |server_component|
      server_cert_name =  server_component['puppetCertName']
      logger.debug "Server cert name: #{server_cert_name}"

      if service_tag = cert_name_to_service_tag(server_cert_name)
        # If we got service tag, it is a dell server and we get inventory
        logger.debug("Server CERT NAME IS: #{server_cert_name}")
        logger.debug("Service Tag: #{service_tag}")
        inventory = ASM::Util.fetch_server_inventory(server_cert_name)
      else
        inventory = nil
      end

      if inventory
        # Putting the re-direction as per the blade type
        # Blade and RACK server
        server_vlan_info = get_server_networks(server_component,server_cert_name)
        blade_type = inventory['serverType'].downcase
        logger.debug("Server Blade type: #{blade_type}")
        if blade_type == "rack"
          logger.debug "Configuring rack server"
          if @configured_rack_switches.length() > 0
            logger.debug "Configuring ToR configuration for server #{server_cert_name}"
            configure_tor(server_cert_name, server_vlan_info)
          else
            logger.debug "INFO: There are no RACK ToR Switches in the ASM Inventory"
          end
        else
          if @configured_blade_switches.length() > 0
            logger.debug "Configuring blade server"
            configure_tor_blade(server_cert_name, server_vlan_info)
          else
            logger.debug "INFO: There are no IOM Switches in the ASM Inventory"
          end
        end
      end
    end
  end

  # SAN Switch configuration needs to be performed
  # only if the SAN Switch configuration flag is set to true
  # And compellent is available in the service template
  def process_san_switches()

    # Check if Compellent is added to the service template
    if !compellent_in_service_template()
      logger.debug "Compellent is not in the service template, skippnig SAN configuration"
      return
    end

    # Get Information from compellent component
    san_info_hash=get_compellent_san_information()
    logger.debug "Configure SAN Value: #{san_info_hash['configure_san_switch']}"
    if !san_info_hash['configure_san_switch']
      logger.debug "Service template has configure SAN switch flag to false,
      skipping SAN switch configuration"
      return
    end

    fcsupport=servers_has_fc_enabled()
    if !fcsupport['returncode']
      logger.error(fcsupport['returnmessage'])
      raise(Exception,"#{fcsupport['returnmessage']}")
    end

    # Reboot all servers to ensure that the WWPN values are accessible on the Brocade switch
    reboot_all_servers()

    # Initiating the discovery of the Brocade switches so that all the values are updated
    initiate_discovery(@brocade_san_switchhash)

    # Get the compellent controller id's, required for mapping of information
    compellent_contollers=compellent_controller_ids()

    # Perform the SAN configuration for each server
    (@components_by_type['SERVER'] || []).each do |server_component|
      server_cert_name =  server_component['puppetCertName']
      logger.debug "Server cert name: #{server_cert_name}"

      if service_tag = cert_name_to_service_tag(server_cert_name)
        # If we got service tag, it is a dell server and we get inventory
        logger.debug("Server CERT NAME IS: #{server_cert_name}")
        logger.debug("Service Tag: #{service_tag}")
        inventory = ASM::Util.fetch_server_inventory(server_cert_name)

        # Get Server WWPN Number
        # If there is no WWPN number identified then, skip the SAN Switch configuration
        wwpns = nil
        wwpns ||= (get_specific_dell_server_wwpns(server_component) || [])
        if wwpns.nil? or (wwpns.length == 0)
          logger.debug "Server do not have any WWPN in the inventory, skip SAN Configuration"
          wwpns=nil
          next
        else
          logger.debug "WWPNs from the WSMAN command: #{wwpns}"

          #new_wwns = wwpns.gsub(/:/, '').split(',')
          #logger.debug "WWPNs identified #{new_wwns}"
        end
      else
        inventory = nil
      end

      if (inventory and wwpns)
        # Putting the re-direction as per the blade type
        # Blade and RACK server
        blade_type = inventory['serverType'].downcase
        logger.debug("Server Blade type: #{blade_type}")
        logger.debug "Configuring SAN Switch"
        configure_san_switch(server_cert_name, wwpns, compellent_contollers)
      else
        logger.debug "Not able to identify server inventory or wwpn information for server #{server_cert_name}"
      end
    end
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
    ['STORAGE', 'TOR', 'SERVER', 'CLUSTER', 'VIRTUALMACHINE', 'TEST'].each do |type|
      if components = @components_by_type[type]
        log("Processing components of type #{type}")
        log("Status: Processing_#{type.downcase}")
        components.collect do |comp|
          #
          # TODO: this is some pretty primitive thread management, we need to use
          # something smarter that actually uses a thread pool
          #
          Thread.new do
            raise(Exception, 'Component has no certname') unless comp['puppetCertName']
            Thread.current[:certname] = comp['puppetCertName']
            send("process_#{type.downcase}", comp)
          end
        end.each do |thrd|
          begin
            thrd.join
            log("Status: Completed_component_#{type.downcase}/#{thrd[:certname]}")
          rescue Exception => e
            log("Status: Failed_component_#{type.downcase}/#{thrd[:certname]}")
            raise(e)
          end
        end
        log("Finsished components of type #{type}")
      end
    end
  end

  def process_generic(
    cert_name,
    config,
    puppet_run_type,
    override = true,
    server_cert_name = nil,
    asm_guid=nil
  )
    raise(Exception, 'Component has no certname') unless cert_name
    log("Starting processing resources for endpoint #{cert_name}")

    if server_cert_name != nil
      resource_file = File.join(resources_dir, "#{cert_name}-#{server_cert_name}.yaml")
    else
      resource_file = File.join(resources_dir, "#{cert_name}.yaml")
    end

    begin
      # The timeout to obtain the device lock was originally 5
      # minutes.  However, the equallogic module currently takes >
      # 5 minutes to provision a single volume which seems
      # unreasonable. An issue was raised for that here:
      #
      # https://github.com/dell-asm/dell-equallogic/issues/6
      #
      # As a short-term workaround to allow at least a few
      # deployments involving the same equallogic to be started
      # simultaneously, the timeout has been raised to 30
      # minutes. When the equallogic issue above has been resolved
      # it should be reduced back down to about 5 minutes.
      timeout = 30 * 60
      start = Time.now
      yet_to_run_command = true
      while(yet_to_run_command)
        if ASM.block_certname(cert_name)
          yet_to_run_command = false
          puppet_out = File.join(deployment_dir, "#{cert_name}.out")
          # synchronize creation of file counter
          resource_file = iterate_resource_file(resource_file)
          File.open(resource_file, 'w') do |fh|
            fh.write(config.to_yaml)
          end
          override_opt = override ? "--always-override " : ""
          noop_opt     = @noop ? '--noop' : ''
          cmd = "sudo puppet asm process_node --debug --trace --filename #{resource_file} --run_type #{puppet_run_type} --statedir #{resources_dir} #{noop_opt} #{override_opt}#{cert_name}"
          logger.debug "Executing the command #{cmd}"

          if @debug
            logger.info("[DEBUG MODE] puppet execution skipped")
          else
            ASM::Util.run_command(cmd, puppet_out)
          end

          if puppet_run_type == 'device'
            update_inventory_through_controller(asm_guid)
          end
        else
          sleep 2
          if Time.now - start > timeout
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
    results = {}
    unless @debug
      # Check results from output of puppet run
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
    end
    results
  end

  #
  # occassionally, the same certificate is re-used by multiple
  # components in the same service deployment. This code checks
  # if a given filename already exists, and creates a different
  # resource file by appending a counter to the end of the
  # resource file name.
  #
  # NOTE : This method is not thread safe. I expects it's calling
  # method to invoke it in a way that is thread safe
  #
  def iterate_resource_file(resource_file)
    if File.exists?(resource_file)
      # search for all files that match our pattern, increment us!
      base_name = File.basename(resource_file, '.yaml')
      dir       = File.dirname(resource_file)
      matching_files = File.join(dir, "#{base_name}___*")
      i = 1
      Dir[matching_files].each do |file|
        f_split   = File.basename(file, '.yaml').split('___')
        num = Integer(f_split.last)
        i = num > i ? num : i
      end
      resource_file = File.join(dir, "#{base_name}___#{i + 1}.yaml")
    else
      resource_file
    end
  end

  def massage_asm_server_params(serial_number, params, classes={})
    if params['rule_number']
      raise(Exception, "Did not expect rule_number in asm::server")
    else
      params['rule_number'] = rule_number
    end

    if params['os_image_type'] == 'vmware_esxi'
      params['broker_type'] = 'noop'
    else
      params['broker_type'] = 'puppet'
    end

    params['serial_number'] = serial_number
    params['policy_name'] = "policy-#{params['os_host_name']}-#{@id}"

    params['cert_name'] = ASM::Util.hostname_to_certname(params['os_host_name'])
    params['puppet_classification_data'] = classes unless classes.empty?

    custom_kickstart_content = (params['custom_script'] || '').strip
    params.delete('custom_script')
    if custom_kickstart_content.length > 0
      custom_script_path = create_custom_script(serial_number,custom_kickstart_content)
      params['custom_script'] = custom_script_path
    end
  end

  #
  # This method is used for collecting server wwpn to
  # provide to compellent for it's processing
  #
  def get_dell_server_wwpns
    log("Processing server component for compellent")
    if components = @components_by_type['SERVER']
      components.collect do |comp|
        cert_name   = comp['puppetCertName']
        dell_service_tag = cert_name_to_service_tag(cert_name)
        # service_tag is only set for Dell servers
        if dell_service_tag
          deviceconf = ASM::Util.parse_device_config(cert_name)
          ASM::WsMan.get_wwpns(deviceconf,logger)
        end
      end.compact.flatten.uniq
    end
  end

  # Get the iSCSI IP Address reserved for each of the server
  # and return the list of IP Addresses
  def get_dell_server_iscsi_ipaddresses()
    iscsi_ip_addresses = []
    if components = @components_by_type['SERVER']
      components.collect do |comp|
        cert_name   = comp['puppetCertName']
        dell_service_tag = cert_name_to_service_tag(cert_name)
        logger.debug "Getting iSCSI IP Address for server #{dell_service_tag}"
        # service_tag is only set for Dell servers
        if dell_service_tag
          server_conf = ASM::Util.build_component_configuration(comp, :decrypt => decrypt?)
          (server_conf['asm::server'] || []).each do |server_cert, server_params|
            net_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
            (net_params || {}).each do |name, net_array|
              if name == 'storage_network'
                unless net_array.size == 2
                  raise("Expected 2 iscsi interfaces for hyperv, only found #{net_array.size}")
                end
                first_net = net_array.first
                iscsi_ip_addresses.push(first_net['staticNetworkConfiguration']['ip_address'])
                iscsi_ip_addresses.push(net_array.last['staticNetworkConfiguration']['ip_address'])
              end
            end

          end
        end
      end
    end
    iscsi_ip_addresses.compact.flatten.uniq
  end

  def get_specific_dell_server_wwpns(comp)
    wwpninfo=nil
    cert_name   = comp['puppetCertName']
    dell_service_tag = cert_name_to_service_tag(cert_name)
    # service_tag is only set for Dell servers
    if dell_service_tag
      deviceconf = ASM::Util.parse_device_config(cert_name)
      ASM::WsMan.get_wwpns(deviceconf,logger)
    end
  end

  def process_test(component)
    config = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)
    process_generic(component['puppetCertName'], config, 'apply', true)
  end

  def process_storage(component)
    log("Processing storage component: #{component['id']}")

    resource_hash = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)

    wwpns = nil
    (resource_hash['compellent::createvol'] || {}).each do |title, params|

      # TODO this can't be right, it should not be all servers, but
      # just those that are related components
      wwpns ||= (get_dell_server_wwpns || [])

      new_wwns = params['wwn'].split(',') + wwpns
      # Replace all the ":" from the WWPN
      # Compellent command-set do not like ":" in the value
      new_wwns = new_wwns.compact.map {|s| s.gsub(/:/, '')}
      resource_hash['compellent::createvol'][title]['wwn'] = new_wwns
      resource_hash['compellent::createvol'][title].delete('configuresan')
    end

    # Process EqualLogic manifest file in case auth_type is 'iqnip'
    (resource_hash['equallogic::create_vol_chap_user_access'] || {}).each do |title, params|
      if ( resource_hash['equallogic::create_vol_chap_user_access'][title]['auth_type'] == "iqnip")
        iscsi_ipaddresses ||= (get_dell_server_iscsi_ipaddresses() || [])
        logger.debug "iSCSI IP Address reserved for the deployment: #{iscsi_ipaddresses}"
        server_template_iqnorip = resource_hash['equallogic::create_vol_chap_user_access'][title]['iqnorip']
        logger.debug "server_template_iqnorip : #{server_template_iqnorip}"
        if !server_template_iqnorip.nil?
          logger.debug "Value of IP or IQN provided"
          new_iscsi_iporiqn = server_template_iqnorip.split(',') + iscsi_ipaddresses
        else
          logger.debug "Value of IP or IQN not provided in service template"
          new_iscsi_iporiqn = iscsi_ipaddresses
        end
        new_iscsi_iporiqn = new_iscsi_iporiqn.compact.map {|s| s.gsub(/ /, '')}
        resource_hash['equallogic::create_vol_chap_user_access'][title]['iqnorip'] = new_iscsi_iporiqn
      end
    end

    process_generic(
      component['puppetCertName'],
      resource_hash,
      'device',
      true,
      nil,
      component['asmGUID']
    )
  end

  def process_tor(component)
    log("Processing tor component: #{component['puppetCertName']}")
    config = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)
    process_generic(component['puppetCertName'], config, 'device')
  end

  def configure_tor(server_cert_name,server_vlan_info)
    inv = nil
    switchhash = {}
    serverhash =  {}

    serverhash = get_server_inventory(server_cert_name)
    logger.debug "******** In process_tor after getServerInventory serverhash is  #{ASM::Util.sanitize(serverhash)} **********\n"
    switchinfoobj = Get_switch_information.new()
    switchportdetail = switchinfoobj.get_info(serverhash,@rack_server_switchhash,logger)
    logger.debug "******** In process_tor switchportdetail :: #{switchportdetail} *********\n"
    tagged_vlaninfo = server_vlan_info["#{server_cert_name}_taggedvlanlist"]
    tagged_workloadvlaninfo = server_vlan_info["#{server_cert_name}_taggedworkloadvlanlist"]
    untagged_vlaninfo = server_vlan_info["#{server_cert_name}_untaggedvlanlist"]
    tagged_vlanlist = tagged_vlaninfo + tagged_workloadvlaninfo
    tagged_vlanlist = tagged_vlanlist.uniq
    common_vlanlist = tagged_vlanlist & untagged_vlaninfo
    tagged_vlanlist = tagged_vlanlist - common_vlanlist
    logger.debug "In configure_tor tagged vlan list found #{tagged_vlanlist}"
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
        tagged_vlanlist.each do |vlanid|
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
          process_generic(switchcertname, resource_hash, 'device', true, server_cert_name)
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
          process_generic(switchcertname, resource_hash, 'device', true, server_cert_name)
        end
      end
    end

  end

  def configure_tor_blade(server_cert_name, server_vlan_info)
    device_conf = nil
    inv = nil
    switchhash = {}
    serverhash = {}
    deviceConfDir ='/etc/puppetlabs/puppet/devices'
    serverhash = get_server_inventory(server_cert_name)
    logger.debug "******** In process_tor after getServerInventory serverhash is #{ASM::Util.sanitize(serverhash)} **********\n"
    switchinfoobj = Get_switch_information.new()
    switchportdetail = switchinfoobj.get_info(serverhash,@blade_server_switchhash,logger)
    logger.debug "******** In process_tor switchportdetail :: #{switchportdetail} *********\n"
    tagged_vlaninfo = server_vlan_info["#{server_cert_name}_taggedvlanlist"]
    tagged_workloadvlaninfo = server_vlan_info["#{server_cert_name}_taggedworkloadvlanlist"]
    untagged_vlaninfo = server_vlan_info["#{server_cert_name}_untaggedvlanlist"]
    tagged_vlanlist = tagged_vlaninfo + tagged_workloadvlaninfo
    tagged_vlanlist = tagged_vlanlist.uniq
    temptagged_vlanlist = untagged_vlaninfo & tagged_vlanlist
    tagged_vlanlist = tagged_vlanlist - temptagged_vlanlist
    logger.debug "In configure_tor tagged vlan list found #{tagged_vlanlist}"
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
          if iom_type == ""
             logger.debug("IOM Type is empty.")
             next
          end

          logger.debug "switchcertname :: #{switchcertname} interface :: #{interface}"
          logger.debug "Configuring tagged VLANs"

          if iom_type == "ioa"
            if switchcertname =~ /dell_iom/
              switch_resource_type = "asm::ioa"
              resource_hash[switch_resource_type] = {
                "#{interface}" => {
                'vlan_tagged' => tagged_vlanlist.join(","),
                'vlan_untagged' => untagged_vlaninfo.join(","),
                }
              }
              logger.debug("*** resource_hash is #{resource_hash} ******")
              process_generic(switchcertname, resource_hash, 'device', true, server_cert_name)
            end
          elsif iom_type == "mxl"
            match = interface.match(/(\w*)(\d.*)/)
            interface = $2
            tagged_vlanlist.each do |vlanid|
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
                process_generic(switchcertname, resource_hash, 'device', true, server_cert_name)
              end
            end # end of tagged vlan loop

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
                process_generic(switchcertname, resource_hash, 'device', true, server_cert_name)
              end

            end

          else
            logger.debug "Non supported IOA type #{iom_type}"
          end

        end

      end
    end

  end

  def configure_san_switch(server_cert_name, wwpns, compellent_contollers)
    device_conf = nil
    inv = nil
    switchhash = {}
    serverhash = {}
    deviceConfDir ='/etc/puppetlabs/puppet/devices'
    serverhash = get_server_inventory(server_cert_name)
    switchinfoobj = Get_switch_information.new()
    switchportdetail = switchinfoobj.get_san_info(serverhash,@brocade_san_switchhash,wwpns,compellent_contollers, logger)

    logger.debug "Start configuring the Brocade SAN Switch for #{server_cert_name}"
    # If there is no information, skip the further configuration
    if switchportdetail.empty?
      logger.debug "No switch details identified"
      return false
    end

    switchportdetail[0].each do |server_wwpn,sw_info|
      if sw_info.empty?
        logger.debug "There is no switch information for WWPN #{server_wwpn}"
        next
      end

      switch_info=sw_info[0]
      switchcertname=switch_info[0]
      switch_port_location=switch_info[1]
      logger.debug"server_wwpn:#{server_wwpn}"
      logger.debug"switch_info: #{switch_info.inspect}"
      logger.debug"switchcertname: #{switchcertname}"
      logger.debug"switch_port_location: #{switch_port_location}"

      if switch_info[2].nil?
        switch_active_zoneset="ASM-Zoneset"
      else
        switch_active_zoneset=switch_info[2]
      end

      switch_storage_alias=switch_info[3]
      logger.debug"switch_active_zoneset: #{switch_active_zoneset}"
      logger.debug"switch_storage_alias:#{switch_storage_alias}"

      service_tag=self.cert_name_to_service_tag(server_cert_name)
      zone_name="ASM_#{service_tag}"

      resource_hash = Hash.new
      resource_hash["brocade::createzone"] = {
        "#{zone_name}" => {
        'storage_alias' => switch_storage_alias,
        'server_wwn' => server_wwpn,
        'zoneset' => switch_active_zoneset
        }
      }
      logger.debug("*** resource_hash is #{resource_hash} ******")
      process_generic(switchcertname, resource_hash, 'device', true, server_cert_name)

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

  #
  # Dell specific servers have the service tag in
  # the certificate name. This method returns a service
  # tag for certificate names of Dell servers and
  # returns nil for non-dell servers
  #
  def cert_name_to_service_tag(title)
    match = /^(bladeserver|rackserver)-(.*)$/.match(title)
    if match
      match[2].upcase
    else
      nil
    end
  end

  def get_server_inventory(certname)
    serverhash = {}
    serverpropertyhash = {}
    serverpropertyhash = Hash.new
    puts "******** In getServerInventory certname is #{certname} **********\n"
    resourcehash = {}
    device_conf = nil
    inv = nil
    device_conf ||= ASM::Util.parse_device_config(certname)
    inv  ||= ASM::Util.fetch_server_inventory(certname)
    logger.debug "******** In getServerInventory device_conf is #{ASM::Util.sanitize(device_conf)}************\n"
    logger.debug "******** In getServerInventory inv is #{inv} **************\n"
    dracipaddress = device_conf[:host]
    dracusername = device_conf[:user]
    dracpassword = device_conf[:password]
    servicetag = inv['serviceTag']
    model = inv['model'].split(' ').last
    logger.debug "servicetag :: #{servicetag} model :: #{model}\n"
    if (model =~ /R620/ || model =~ /R720/)
      serverpropertyhash['bladetype'] = "rack"
    else
      serverpropertyhash['bladetype'] = "blade"
      chassis_conf ||= ASM::Util.chassis_inventory(servicetag, logger)
      logger.debug "*********chassis_conf :#{ASM::Util.sanitize(chassis_conf)}"
      serverpropertyhash['chassis_ip'] = chassis_conf['chassis_ip']
      serverpropertyhash['chassis_username'] = chassis_conf['chassis_username']
      serverpropertyhash['chassis_password'] = chassis_conf['chassis_password']
      serverpropertyhash['slot_num'] = chassis_conf['slot_num']
      serverpropertyhash['ioaips'] = chassis_conf['ioaips']
      serverpropertyhash['ioaslots'] = chassis_conf['ioaslots']
    end
    serverpropertyhash['servermodel'] = model
    serverpropertyhash['idrac_ip'] = dracipaddress
    serverpropertyhash['idrac_username'] =  dracusername
    serverpropertyhash['idrac_password'] = dracpassword

    serverpropertyhash['mac_addresses'] = ASM::WsMan.get_mac_addresses(device_conf, model, logger)
    logger.debug "******* In getServerInventory server property hash is #{ASM::Util.sanitize(serverpropertyhash)} ***********\n"
    serverhash["#{servicetag}"] = serverpropertyhash
    logger.debug "********* In getServerInventory server Hash is #{ASM::Util.sanitize(serverhash)}**************\n"
    return serverhash
  end

  def get_all_switches()
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
        @configured_rack_switches.push(switchCert)
      end
      if line =~ /dell_powerconnect/
        logger.debug "Found dell powerconnect certificate"
        res = line.to_s.strip.split(' ')
        switchCert = res[1]
        switchCert = switchCert.gsub(/\"/, "")
        puts "Powerconnect switch certificate is #{switchCert}"
        @configured_rack_switches.push(switchCert)
      end
      if line =~ /dell_iom/
        logger.debug "Found dell powerconnect certificate"
        res = line.to_s.strip.split(' ')
        switchCert = res[1]
        switchCert = switchCert.gsub(/\"/, "")
        puts "Powerconnect switch certificate is #{switchCert}"
        @configured_blade_switches.push(switchCert)
      end
      if line =~ /brocade_/
        logger.debug "Found brocade switch certificate"
        res = line.to_s.strip.split(' ')
        switchCert = res[1]
        switchCert = switchCert.gsub(/\"/, "")
        puts "Brocade SAN switch certificate is #{switchCert}"
        @configured_brocade_san_switches.push(switchCert)
      end
    end
    @configured_rack_switches.uniq
    @configured_blade_switches.uniq
    @configured_brocade_san_switches.uniq()
    logger.debug "Rack ToR Switch certificate name list is #{@configured_rack_switches}"
    logger.debug "Blade IOM Switch certificate name list is #{@configured_blade_switches}"
    logger.debug "Brocade SAN Switches certificate name list is #{@configured_brocade_san_switches}"
  end

  def populate_rack_switch_hash
    deviceConfDir ='/etc/puppetlabs/puppet/devices'
    switchhash = {}
    @configured_rack_switches.each do |certname|
      logger.debug "****************** certname :: #{certname} ********************"
      conf_file = File.join(deviceConfDir, "#{certname}.conf")
      if !File.exist?(conf_file)
        next
      end
      device_conf = nil
      switchpropertyhash = {}
      switchpropertyhash = Hash.new
      device_conf ||= ASM::Util.parse_device_config(certname)
      logger.debug "******* In process_tor device_conf is #{ASM::Util.sanitize(device_conf)}***********\n"
      torip = device_conf[:host]
      torusername = device_conf[:user]
      torpassword = device_conf['password']
      torurl = device_conf['url']
      logger.debug "******  #{ASM::Util.sanitize(device_conf)} ******"
      logger.debug "tor url :: #{torurl}\n"
      switchpropertyhash['connection_url'] = torurl
      if certname =~ /dell_ftos/
        switchpropertyhash['device_type'] = "dell_ftos"
      else
        switchpropertyhash['device_type'] = "dell_powerconnect"
      end
      logger.debug "********* switch property hash is #{switchpropertyhash} *************\n"
      switchhash["#{certname}"] = switchpropertyhash
      logger.debug "********* switch hash is #{switchhash} *************\n"
    end
    switchhash
  end

  def populate_brocade_san_switch_hash
    deviceConfDir ='/etc/puppetlabs/puppet/devices'
    switchhash = {}
    @configured_brocade_san_switches.each do |certname|
      logger.debug "****************** certname :: #{certname} ********************"
      conf_file = File.join(deviceConfDir, "#{certname}.conf")
      if !File.exist?(conf_file)
        next
      end
      device_conf = nil
      switchpropertyhash = {}
      switchpropertyhash = Hash.new
      device_conf ||= ASM::Util.parse_device_config(certname)
      logger.debug "******* In process_tor device_conf is  #{ASM::Util.sanitize(device_conf)}***********\n"
      torip = device_conf[:host]
      torusername = device_conf[:user]
      torpassword = device_conf['password']
      torurl = device_conf['url']
      logger.debug "******  #{ASM::Util.sanitize(device_conf)} ******"
      logger.debug "tor url :: #{torurl}\n"
      switchpropertyhash['connection_url'] = torurl
      if certname =~ /brocade_fos/
        switchpropertyhash['device_type'] = "brocade_fos"
      else
        logger.debug "non-supported switch type #{certname}"
        next
      end
      logger.debug "********* switch property hash is #{switchpropertyhash} *************\n"
      switchhash["#{certname}"] = switchpropertyhash
      logger.debug "********* Brocade switch hash is #{switchhash} *************\n"
    end
    switchhash
  end

  def populate_blade_switch_hash
    deviceConfDir ='/etc/puppetlabs/puppet/devices'
    switchhash = {}
    @configured_blade_switches.each do |certname|
      logger.debug "****************** certname :: #{certname} ********************"
      conf_file = File.join(deviceConfDir, "#{certname}.conf")
      if !File.exist?(conf_file)
        next
      end
      device_conf = nil
      switchpropertyhash = {}
      switchpropertyhash = Hash.new
      device_conf ||= ASM::Util.parse_device_config(certname)
      logger.debug "******* In process_tor device_conf is  #{ASM::Util.sanitize(device_conf)} ***********\n"
      torip = device_conf[:host]
      torusername = device_conf[:user]
      torpassword = device_conf['password']
      torurl = device_conf['url']
      logger.debug "******  #{ASM::Util.sanitize(device_conf)} ******"
      logger.debug "tor url :: #{torurl}\n"
      switchpropertyhash['connection_url'] = torurl
      if certname =~ /dell_ftos/
        switchpropertyhash['device_type'] = "dell_ftos"
      else
        switchpropertyhash['device_type'] = "dell_powerconnect"
      end
      logger.debug "********* switch property hash is #{switchpropertyhash} *************\n"
      switchhash["#{certname}"] = switchpropertyhash
      logger.debug "********* switch hash is #{switchhash} *************\n"
    end
    switchhash
  end

  def process_server(component)
    log("Processing server component: #{component['puppetCertName']}")
    cert_name = component['puppetCertName']

    # In the case of Dell servers the cert_name should contain
    # the service tag and we retrieve it here
    serial_number = nil
    service_tag = cert_name_to_service_tag(cert_name)
    if service_tag
      is_dell_server = true
      serial_number = service_tag
    else
      is_dell_server = false
      serial_number = cert_name
    end
    resource_hash = {}
    server_vlan_info = {}
    deviceconf = nil
    inventory = nil
    os_host_name = nil
    resource_hash = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)

    if resource_hash['asm::server']
      if resource_hash['asm::server'].size != 1
        msg = "Only one O/S configuration allowed per server; found #{resource_hash['asm::server'].size} for #{serial_number}"
        logger.error(msg)
        raise(Exception, msg)
      end

      title = resource_hash['asm::server'].keys[0]
      params = resource_hash['asm::server'][title]
      os_image_type = params['os_image_type']
      os_host_name  = params['os_host_name']
      classes_config = get_classification_data(component, os_host_name)
      massage_asm_server_params(serial_number, params, classes_config)
    end

    # Create a vmware ks.cfg include file containing esxcli command line
    # calls to create a static management network that will be executed
    # from the vmware ks.cfg
    static_ip = nil
    if resource_hash['asm::esxiscsiconfig']
      if resource_hash['asm::esxiscsiconfig'].size != 1
        msg = "Only one ESXi networking configuration allowed per server; found #{resource_hash['asm::esxiscsiconfig'].size} for #{serial_number}"
        logger.error(msg)
        raise(Exception, msg)
      end

      title = resource_hash['asm::esxiscsiconfig'].keys[0]
      network_params = resource_hash['asm::esxiscsiconfig'][title]
      mgmt_networks = network_params['hypervisor_network']
      if mgmt_networks
        if mgmt_networks.size != 1
          msg = "Only one hypervisor network allowed, found #{mgmt_networks.size}"
          logger.error(msg)
          raise(Exception, msg)
        end
        mgmt_network = mgmt_networks[0]
        static = mgmt_network['staticNetworkConfiguration']
        unless static
          # This should have already been checked previously
          msg = "Static network is required for hypervisor network"
          logger.error(msg)
          raise(Exception, msg)
        end

        static_ip = static['ip_address']
        content = "network --bootproto=static --device=vmnic0 --ip=#{static_ip}  --netmask=#{static['subnet']} --gateway=#{static['gateway']}"
        # NOTE: vlanId is a FixNum
        if mgmt_network['vlanId']
          content += " --vlanid=#{mgmt_network['vlanId']}"
        end
        nameservers = [ static['dns1'], static['dns2'] ].select { |x| !x.nil? && !x.empty? }
        if nameservers.size > 0
          content += " --nameserver=#{nameservers.join(',')}"
        else
          content += ' --nodns'
        end
        if os_host_name
          content += " --hostname='#{os_host_name}'"
        end
        content += "\n"

        resource_hash['file'] = {}
        resource_hash['file'][cert_name] = {
          'path' => "/opt/razor-server/installers/vmware_esxi/bootproto_#{serial_number}.inc.erb",
          'content' => content,
          'owner' => 'razor',
          'group' => 'razor',
          'mode' => '0644',
        }
      end
    end

    if is_dell_server && resource_hash['asm::idrac']
      if resource_hash['asm::idrac'].size != 1
        msg = "Only one iDrac configuration allowed per server; found #{resource_hash['asm::idrac'].size} for #{serial_number}"
        logger.error(msg)
        raise(Exception, msg)
      end

      title = resource_hash['asm::idrac'].keys[0]
      params = resource_hash['asm::idrac'][title]
      deviceconf = ASM::Util.parse_device_config(cert_name)
      inventory = ASM::Util.fetch_server_inventory(cert_name)
      params['nfsipaddress'] = ASM::Util.get_preferred_ip(deviceconf[:host])
      params['nfssharepath'] = '/var/nfs/idrac_config_xml'
      params['servicetag'] = inventory['serviceTag']
      params['model'] = inventory['model'].split(' ').last.downcase
      params['before'] = []
      if resource_hash['asm::server']
        params['before'].push("Asm::Server[#{cert_name}]")
      end
      if resource_hash['file']
        params['before'].push("File[#{cert_name}]")
      end
      if resource_hash['file']
        params['']
      end
    end

    if os_image_type == 'hyperv'
      storage = ASM::Util.asm_json_array(
                  find_related_components('STORAGE', component)
                )
      target_devices = []
      vol_names      = []
      storage.each do |c|
        target_devices.push(c['puppetCertName'])
        ASM::Util.asm_json_array(c['resources']).each do |r|
          if r['id'] == 'equallogic::create_vol_chap_user_access'
            r['parameters'].each do |param|
              if param['id'] == 'title'
                vol_names.push(param['value'])
              end
            end
          end
        end
      end
      unless target_devices.uniq.size == 1
        raise(Exception, "Expected to find only one target ip, found #{target_devices.uniq.size}")
      end
      unless vol_names.size == 2
        raise(Exception, "Expected to find two volumes, found #{vol_names.size}")
      end
      disk_part_flag = get_disk_part_flag(component)
      target_ip = ASM::Util.find_equallogic_iscsi_ip(target_devices.first)
      resource_hash = ASM::Processor::Server.munge_hyperv_server(
                        title,
                        resource_hash,
                        target_ip,
                        vol_names,
                        disk_part_flag
                      )
    end

    # The rest of the asm::esxiscsiconfig is used to configure vswitches
    # and portgroups on the esxi host and is done in the cluster swimlane
    resource_hash.delete('asm::esxiscsiconfig')

    # Check whether we should skip calling process_generic based on
    # whether the server already seems to be installed with the correct
    # O/S. Don't bother doing this if we are @debug since we do not
    # actually execute any puppet commands in that case any way.
    skip_deployment = nil
    unless @debug
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
    end

    if skip_deployment
      # In theory the puppet razor and idrac modules should be idempotent
      # and we could call process_generic without affecting them if they
      # are already in the desired state. However, the idrec module
      # currently always reboots the server
      log("Skipping deployment of #{cert_name}; already complete.")
    else
      process_generic(component['puppetCertName'], resource_hash, 'apply', 'true')
      unless @debug
        (resource_hash['asm::server'] || []).each do |title, params|
          type = params['os_image_type']
          if type == 'vmware_esxi'
            raise(Exception, "Static management IP address was not specified for #{serial_number}") unless static_ip
            block_until_esxi_ready(title, params, static_ip, timeout=3600)
          else
            deployment_status = await_agent_run_completion(ASM::Util.hostname_to_certname(os_host_name), timeout = 3600)
            if (deployment_status and os_image_type == 'hyperv')
               hyperv_post_installation(ASM::Util.hostname_to_certname(os_host_name), cert_name, timeout=3600)
            end
          end
        end
      end
      update_inventory_through_controller(component['asmGUID'])
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


  def mark_vcenter_as_needs_update(vcenter_guid)
    (@vcenter_to_refresh ||= []).push(vcenter_guid)
  end

  def update_vcenters
    (@vcenter_to_refresh || []).uniq.each do |vc_guid|
      update_inventory_through_controller(vc_guid)
    end
  end

  # calls the Java controller to update the inventory service
  def update_inventory_through_controller(asm_guid)
    unless @debug
      if asm_guid.nil?
        # TODO: this clause should never be hit, but currently switch
        # devices which do not have asm guids are making it to this
        # section of code from the device section of
        # process_generic. We should change the update to only happen
        # in a method that specific swim lanes (e.g. process_storage)
        # can call, but for now we just skip inventory for them
        logger.debug("Skipping inventory because asm_guid is empty")
      else
        logger.debug("Updating inventory for #{asm_guid}")
        url      = "http://localhost:9080/AsmManager/ManagedDevice/#{asm_guid}"
        asm_obj  = JSON.parse(RestClient.get(url, :content_type => :json, :accept => :json))
        response = RestClient.put(url, asm_obj.to_json,  :content_type => :json, :accept => :json)
      end
    end
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
    portgrouptype, active_nics, network_type)
    ret = {
      'name' => "#{hostip}:#{portgroup_name}",
      'ensure' => 'present',
      'portgrouptype' => portgrouptype,
      'overridefailoverorder' => 'disabled',
      'failback' => true,
      'mtu' => network_type == 'storage_network' ? 9000 : 1500,
      'overridefailoverorder' => 'enabled',
      'nicorderpolicy' => {
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
      'vmotion' => network_type == 'vmotion_network' ? 'enabled' : 'disabled',
      'path' => path,
      'host' => hostip,
      'vlanid' => network['vlanId'],
      'transport' => 'Transport[vcenter]'
    }
  end

  def build_vswitch(server_cert, index, networks, hostip,
    params, server_params, network_type)
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
      'mtu' => index == 3 ? 9000 : 1500,
      'checkbeacon' => true,
      'transport' => 'Transport[vcenter]',
    }

    portgrouptype = 'VMkernel'
    next_require = "Esx_vswitch[#{hostip}:#{vswitch_name}]"

    portgroup_names = nil
    if network_type == 'storage_network'
      # iSCSI network
      # NOTE: We have to make sure the ISCSI1 requires ISCSI0 so that
      # they are created in the "right" order -- the order that will
      # give ISCSI0 vmk2 and ISCSI1 vmk3 vmknics. The datastore
      # configuration relies on that.
      portgroup_names = [ 'ISCSI0', 'ISCSI1' ]
      raise(Exception, "Exactly two networks expected for storage network") unless networks.size == 2
    else
      if network_type == 'workload_network'
        portgrouptype = 'VirtualMachine'
      end
      portgroup_names = networks.map { |network| network['name'] }
      if index == 0
        # Hypervisor network. Currently the static management ip is
        # set in the esxi kickstart and has a name of "Management
        # Network". We have to match that name in order to be able to
        # change the settings for that portgroup since they are
        # configured by name.
        portgroup_names[0] = 'Management Network'
      end
    end

    portgroup_names.each_with_index do |portgroup_name, index|
      network = networks[index]
      portgroup_title = "#{hostip}:#{portgroup_name}"
      active_nics = network_type == 'storage_network' ? [nics[index]] : nics
      portgroup = build_portgroup(vswitch_name, path, hostip, portgroup_name,
      network, portgrouptype, active_nics, network_type)

      static = network['staticNetworkConfiguration']

      if static
        # TODO: we should consolidate our reservation requests
        reservation_guid = "#{@id}-#{portgroup_title}"
        ip = static['ip_address'] || raise(Exception, "ip_address not set")
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

  def copy_endpoint(endpoint, ip)
    ret = endpoint.dup
    ret[:host] = ip
    ret
  end

  def process_cluster(component)
    cert_name = component['puppetCertName']
    raise(Exception, 'Component has no certname') unless cert_name
    log("Processing cluster component: #{cert_name}")

    resource_hash = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)

    # Assuming there is a parameters to categorized the cluster type
    (resource_hash['asm::cluster::scvmm'] || {}).each do |title,params|
      configure_hyperv_cluster(component,resource_hash,title)
    end

    (resource_hash['asm::cluster'] || {}).each do |title, params|
      resource_hash['asm::cluster'][title]['vcenter_options'] = { 'insecure' => true }
      resource_hash['asm::cluster'][title]['ensure'] = 'present'

      # Add ESXi hosts and creds as separte resources
      (find_related_components('SERVER', component) || []).each do |server_component|
        server_conf = ASM::Util.build_component_configuration(server_component, :decrypt => decrypt?)

        (server_conf['asm::server'] || []).each do |server_cert, server_params|
          if server_params['os_image_type'] == 'vmware_esxi'
            serial_number = cert_name_to_service_tag(server_cert)
            unless serial_number
              serial_number = server_cert
            end

            # Determine host IP
            log("Finding host ip for serial number #{serial_number}")
            hostip = find_host_ip(serial_number)
            if @debug && !hostip
              hostip = "DEBUG-IP-ADDRESS"
            end
            network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
            mgmt_networks = network_params['hypervisor_network']
            if mgmt_networks
              if mgmt_networks.size != 1
                msg = "Only one hypervisor network allowed, found #{mgmt_networks.size}"
                logger.error(msg)
                raise(Exception, msg)
              end
              mgmt_network = mgmt_networks[0]
              static = mgmt_network['staticNetworkConfiguration']
              unless static
                # This should have already been checked previously
                msg = "Static network is required for hypervisor network"
                logger.error(msg)
                raise(Exception, msg)
              end
              hostip = static['ip_address']
            end

            raise(Exception, "Could not find host ip for #{server_cert}") unless hostip
            serverdeviceconf = ASM::Util.parse_device_config(server_cert)

            # Add esx hosts to cluster
            resource_hash['asm::host'] ||= {}
            resource_hash['asm::host'][server_cert] = {
              'datacenter' => params['datacenter'],
              'cluster' => params['cluster'],
              'hostname' => hostip,
              'username' => ESXI_ADMIN_USER,
              'password' => server_params['admin_password'],
              'decrypt'  => decrypt?,
              'require' => "Asm::Cluster[#{title}]"
            }

            if network_params
              # Add vswitch config to esx host
              resource_hash['asm::vswitch'] ||= {}

              next_require = "Asm::Host[#{server_cert}]"
              host_require = next_require
              storage_network_require = nil
              storage_network_vmk_index = nil

              # Each ESXi host will implicitly have a Management Network
              # on vmk0. Other VMkernel portgroups that we add will enumerate
              # from there.
              vmk_index = 0

              [ 'hypervisor_network', 'vmotion_network', 'workload_network', 'storage_network' ].each_with_index do | type, index |
                networks = network_params[type]

                if networks
                  # For workload, guid may be a comma-separated list
                  networks.each_with_index do |network, index|
                    # Storage network has two duplicate networks for
                    # iSCSI configuration, only log one message for it
                    unless type == 'storage_network' && index > 0
                      log("Configuring #{type} #{network['name']}")
                    end
                  end
                  vswitch_resources = build_vswitch(server_cert, index,
                  networks, hostip,
                  params, server_params, type)
                  # Should be exactly one vswitch in response
                  vswitch_title = vswitch_resources['esx_vswitch'].keys[0]
                  vswitch = vswitch_resources['esx_vswitch'][vswitch_title]
                  vswitch['require'] = next_require

                  # Set next require to this vswitch so they are all
                  # ordered properly
                  next_require = "Esx_vswitch[#{vswitch_title}]"
                  vswitch_resources['esx_portgroup'].each do |title, portgroup|
                    # Enforce very strict ordering of each vswitch,
                    # its portgroups, then the next vswitch, etc.
                    # This is necessary to guess what vmk the portgroups
                    # end up on so that the datastore can be configured.
                    next_require = "Esx_portgroup[#{title}]"

                    # Increment vmk_index except for hypervisor_network which will
                    # always be vmk0
                    if portgroup['portgrouptype'] == 'VMkernel' && type != 'hypervisor_network'
                      vmk_index += 1
                    end

                    if type == 'storage_network'
                      storage_network_require ||= []
                      storage_network_vmk_index ||= vmk_index
                      storage_network_require.push("Esx_portgroup[#{title}]")
                    end

                  end

                  # merge these in
                  resource_hash['esx_vswitch'] = (resource_hash['esx_vswitch'] || {}).merge(vswitch_resources['esx_vswitch'])
                  resource_hash['esx_portgroup'] = (resource_hash['esx_portgroup'] || {}).merge(vswitch_resources['esx_portgroup'])
                end
              end

              logger.debug('Configuring the storage manifest')
              (find_related_components('STORAGE', server_component) || []).each do |storage_component|
                storage_cert = storage_component['puppetCertName']
                storage_creds = ASM::Util.parse_device_config(storage_cert)
                storage_hash = ASM::Util.build_component_configuration(storage_component, :decrypt => decrypt?)

                esx_password = server_params['admin_password']
                if decrypt?
                  esx_password = ASM::Cipher.decrypt_string(esx_password)
                end

                if storage_hash['equallogic::create_vol_chap_user_access']
                  # Configure iscsi datastore
                  if @debug
                    hba_list = [ 'vmhba33', 'vmhba34' ]
                  else
                    hba_list = parse_hbas(hostip, ESXI_ADMIN_USER, esx_password)
                  end
                  raise(Exception, "Network not setup for #{server_cert}") unless storage_network_vmk_index

                  storage_hash['equallogic::create_vol_chap_user_access'].each do |storage_title, storage_params|
                    resource_hash['asm::datastore'] ||= {}
                    resource_hash['asm::datastore']["#{hostip}:datastore"] ||= {
                      'data_center' => params['datacenter'],
                      'datastore' => params['datastore'],
                      'cluster' => params['cluster'],
                      'ensure' => 'present',
                      'esxhost' => hostip,
                      'esxusername' => 'root',
                      'esxpassword' => server_params['admin_password'],
                      'hba1' => hba_list[0],
                      'hba2' => hba_list[1],
                      'iscsi_target_ip' => ASM::Util.find_equallogic_iscsi_ip(storage_cert),
                      'chapname' => storage_params['chap_user_name'],
                      'chapsecret' => storage_params['passwd'],
                      'vmknics' => "vmk#{storage_network_vmk_index}",
                      'vmknics1' => "vmk#{storage_network_vmk_index + 1}",
                      'decrypt' => decrypt?,
                      'require' => storage_network_require,
                    }
                    resource_hash['esx_datastore'] ||= {}
                    resource_hash['esx_datastore']["#{hostip}:#{storage_title}"] ={
                      'ensure' => 'present',
                      'type' => 'vmfs',
                      'lun' => '0',
                      'require' => "Asm::Datastore[#{hostip}:datastore]",
                      'transport' => 'Transport[vcenter]'
                    }

                    # Esx_mem configuration is below
                    if server_params.has_key? 'esx_mem' and server_params['esx_mem'].downcase == 'true'
                      vnics = resource_hash['esx_vswitch']["#{hostip}:vSwitch3"]['nics'].map do|n|
                        n.strip
                      end
                      vnics_ipaddress = []
                      ['ISCSI0', 'ISCSI1'].each do |port|
                        vnics_ipaddress += [ resource_hash['esx_portgroup']["#{hostip}:#{port}"]['ipaddress'].strip ]
                      end

                      vnics_ipaddress = vnics_ipaddress.join(',')
                      vnics = vnics.join(',')

                      logger.debug "Server params: #{server_params}"
                      esx = {
                        'require'                => [
                          "Esx_datastore[#{hostip}:#{storage_title}]",
                          "Esx_syslog[#{hostip}]"],
                        'configure_mem'          => true,
                        'install_mem'            => true,
                        'script_executable_path' => '/opt/Dell/scripts/EquallogicMEM',
                        'setup_script_filepath'  => 'setup.pl',
                        'host_username'          => ESXI_ADMIN_USER,
                        'host_password'          => server_params['admin_password'],
                        'transport'              => "Transport[vcenter]",
                        'storage_groupip'        => ASM::Util.find_equallogic_iscsi_ip(storage_cert),
                        'iscsi_netmask'          => ASM::Util.find_equallogic_iscsi_netmask(storage_cert),
                        'iscsi_vswitch'          => 'vSwitch3',  
                        'vnics'                  => vnics,
                        'vnics_ipaddress'        => vnics_ipaddress
                      }
                      if storage_params.has_key? 'chap_user_name' and not storage_params['chap_user_name'].empty?
                        chap = {
                          'iscsi_chapuser'         => storage_params['chap_user_name'],
                          'iscsi_chapsecret'       => storage_params['passwd'] }
                        esx.merge! chap 
                      end
                      resource_hash['esx_mem'] ||= {}
                      resource_hash['esx_mem'][hostip] = esx
                    end
                  end
                end

                if storage_hash['compellent::createvol']
                  # Configure fiber channel datastore

                  storage_hash['compellent::createvol'].each do |volume, storage_params|
                    folder = storage_params['volumefolder']
                    asm_guid = storage_component['asmGUID']

                    if @debug
                      lun_id = 0
                    else
                      device_id = ASM::Util.find_compellent_volume_info(asm_guid, volume, folder, logger)
                      logger.debug("Compellent Volume info: #{device_id}")
                      decrypt_password=server_params['admin_password']
                      if decrypt?
                        decrypt_password = ASM::Cipher.decrypt_string(server_params['admin_password'])
                      end
                      lun_id = get_compellent_lunid(hostip, 'root', decrypt_password, device_id)
                    end

                    logger.debug("Volume's LUN ID: #{lun_id}")

                    
                    resource_hash['asm::fcdatastore']["#{hostip}:#{volume}"] = {
                      'data_center' => params['datacenter'],
                      'datastore' => params['datastore'],
                      'cluster' => params['cluster'],
                      'ensure' => 'present',
                      'esxhost' => hostip,
                      'lun' => lun_id,
                      'require' => host_require
                    }
                  end
                end
              end
              logger.debug('Configuring persistent storage for logs')
              if params['datastore']
                resource_hash['esx_syslog'] ||= {}
                resource_hash['esx_syslog'][hostip] = {
                  'log_dir_unique' => true,
                  'transport' => 'Transport[vcenter]',
                  'log_dir' => "[#{params['datastore']}] logs"
                }
              end
            end
          end
        end
      end
      # Moving the code inside the loop to ensure it do not conflict with HyperV Cluster
      process_generic(cert_name, resource_hash, 'apply')
      # Running into issues with hosts not coming out of maint mode
      # Try it again for good measure.
      process_generic(cert_name, resource_hash, 'apply')
      mark_vcenter_as_needs_update(component['asmGUID'])
    end
  end

  def parse_hbas(hostip, username, password)
    log("getting hba information for #{hostip}")
    endpoint = {
      :host => hostip,
      :user => username,
      :password => password,
    }
    cmd = 'iscsi adapter list'.split
    h_list = ASM::Util.esxcli(cmd, endpoint, logger)
    if h_list.nil? or h_list.empty?
      msg = "Did not find any iSCSI adapters for #{hostip}"
      logger.error(msg)
      raise(Exception, msg)
    end
    hba_list = h_list.sort_by{|hba| hba['Adapter'][/[0-9]+/].to_i }.select do |hba|
      hba['Description'].end_with?('iSCSI Adapter')
    end.map { |hba| hba['Adapter'] }

    if hba_list.count > 2
      log("Found iSCSI adapters #{hba_list.join(', ')} for #{hostip}; using #{hba_list[0]} and #{hba_list[1]} for datastore")
    elsif hba_list.count < 2
      raise "At least 2 iSCSI adapters are required."
    else
      log("Found iSCSI adapters #{hba_list[0]} and #{hba_list[1]} for #{hostip}")
    end
    hba_list
  end

  def process_virtualmachine(component)
    log("Processing virtualmachine component: #{component['puppetCertName']}")
    resource_hash = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)

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
    raise(Exception, "Expected one cluster for #{component['puppetCertName']} but found #{clusters.size}") unless clusters.size == 1
    cluster = clusters[0]
    cluster_deviceconf = ASM::Util.parse_device_config(cluster['puppetCertName'])
    cluster_resource_hash = ASM::Util.build_component_configuration(cluster, :decrypt => decrypt?)
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
      vm_params['os_guest_id'] = 'windows8Server64Guest'
      vm_params['scsi_controller_type'] = 'LSI Logic SAS'
    else
      vm_params['os_type'] = 'linux'
      vm_params['os_guest_id'] = 'rhel6_64Guest'
      vm_params['scsi_controller_type'] = 'VMware Paravirtual'
    end

    vm_params['cluster'] = cluster_params['cluster']
    vm_params['datacenter'] = cluster_params['datacenter']
    vm_params['datastore'] = cluster_params['datastore']
    vm_params['vcenter_id'] = cluster['puppetCertName']
    vm_params['vcenter_options'] = { 'insecure' => true }
    vm_params['ensure'] = 'present'

    #Added for multiple vm networks
    n_i = [{'portgroup' => 'VM Network', 'nic_type' => 'vmxnet3'}]
    vm_params['network_interfaces'].split(',').reject { |x| x.empty? }.each do |portgroup|
      n_i << {'portgroup' => portgroup, 'nic_type' => 'vmxnet3'}
    end
    vm_params['network_interfaces'] = n_i

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

      # Work around incorrect name in GUI for now
      # TODO: remove when no longer needed
      old_image_param = server_params.delete('os_type')
      if old_image_param
        @logger.warn('Incorrect os image param name os_type')
        server_params['os_image_type'] = old_image_param
      end

      serial_number = @debug ? "vmware_debug_serial_no" : ASM::Util.vm_uuid_to_serial_number(uuid)

      #Get the list of related services to this virtual machine, and combine them into one hash
      classes_config = get_classification_data(component, hostname)

      massage_asm_server_params(serial_number, server_params, classes_config)

      resource_hash['asm::server'] = { hostname => server_params }
      process_generic(vm_cert_name, resource_hash, 'apply')

      unless @debug
        await_agent_run_completion(ASM::Util.hostname_to_certname(hostname))
      end
    end
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

  def await_agent_run_completion(certname, timeout = 3600)
    #get the time that this method starts so can check for reports that happen afterwards
    function_start = Time.now


    ASM::Util.block_and_retry_until_ready(timeout, CommandException, 60) do\
      # check if cert is in list of active nodes
      log("Waiting for puppet agent to check in for #{certname}")
      query_str = "[\"and\", [\"=\", [\"node\", \"active\"], true], [\"=\", \"name\", \"#{certname}\"]]]"
      node_url = "http://localhost:7080/v3/nodes?query=#{URI.escape(query_str)}"
      resp = JSON.parse(RestClient.get(node_url, :content_type=> :json, :accept => :json))
      if resp.size == 0
        raise(CommandException, "Node #{certname} has not checked in.  Retrying...")
      end

      #get the latest report
      query_str = "[\"=\", \"certname\", \"#{certname}\"]"
      order_str = "[{\"field\": \"receive-time\", \"order\": \"desc\"}]"
      report_url = "http://localhost:7080/v3/reports?query=#{URI.escape(query_str)}&order-by=#{URI.escape(order_str)}&limit=1"
      resp = JSON.parse(RestClient.get(report_url, :content_type=> :json, :accept => :json))
      if resp.size == 0
        raise(CommandException, "No reports for #{certname}.  Retrying...")
      end

      #Check if report ended after the await_agent_run_completion function started
      #The agent shouldn't check in so fast that it checks in before this function has been called.  Takes many minutes to provision/insall OS
      report_receive_time = Time.parse(resp.first["receive-time"])
      if(report_receive_time < function_start)
        raise(CommandException, "Reports found, but not from recent runs.  Retrying...")
      end


      report_id = resp.first["hash"]

      query_str = "[\"=\", \"report\", \"#{report_id}\"]"
      events_url = "http://localhost:7080/v3/events?query=#{URI.escape(query_str)}"
      resp = JSON.parse(RestClient.get(events_url, :content_type => :json, :accept => :json))
      if resp.size == 0
          @logger.warn("No events for the latest report for agent #{certname}. Deployment run will continue.")
      elsif resp.any?{|event| event["status"] =="failure"}
        raise(PuppetEventException, "A recent Puppet event for the node #{certname} has failed.  Node may not be correctly configured.")
      end

      log("Agent #{certname} has completed a puppet run")
      true
    end
  end

  def hyperv_post_installation(os_host_name,certname,timeout = 3600)
    # Reboot the server
    serverhash = get_server_inventory(certname)
    endpoint = {}
    serverhash.each do |nodename,sinfo|
      endpoint = {
        :host => sinfo['idrac_ip'],
        :user => sinfo['idrac_username'],
        :password => sinfo['idrac_password']
      }
    end
    ASM::WsMan.reboot(endpoint, logger)
    log("Agent #{certname} has been rebooted to initiate post-installation")
    log("Agent #{certname} - waiting for 10 minutes before validating the post-installation status")
    sleep(600)
    # Wait for the server to go to power-off state
    ASM::Util.block_and_retry_until_ready(timeout, CommandException, 60) do\
      powerstate = ASM::WsMan.get_power_state(endpoint, logger)
      if powerstate.to_i != 13
        raise(CommandException, "Post installation for Server #{certname} still in progress .  Retrying...")
        log("Post installation for Server #{certname} still in progress .  Retrying...")
      end
    end
    log("Post installation for Server #{certname} is completed")

    # Power-on the server
    log("Rebooting server #{certname}")
    ASM::WsMan.reboot(endpoint, logger)

    # Wait puppet agent to respond
    log("Agent #{certname} Waiting for puppet agent to respond after reboot")
    await_agent_run_completion(os_host_name,timeout = 3600)
    true
  end

  # converts from an ASM style server resource into
  # a method call to check if the esx host is up
  def block_until_esxi_ready(title, params, static_ip, timeout=3600)
    serial_num = params['serial_number'] || raise(Exception, "resource #{title} is missing required server attribute admin_password")
    password = params['admin_password'] || raise(Exception, "resource #{title} is missing required server attribute admin_password")
    if decrypt?
      password = ASM::Cipher.decrypt_string(password)
    end
    type = params['os_image_type'] || raise(Exception, "resource #{title} is missing required server attribute os_image_type")
    hostname = params['os_host_name'] || raise(Exception, "resource #{title} is missing required server attribute os_host_name")
    hostdisplayname = "#{serial_num} (#{hostname})"

    log("Waiting until #{hostdisplayname} has checked in with Razor")
    dhcp_ip = find_host_ip_blocking(serial_num, timeout)
    log("#{hostdisplayname} has checked in with Razor with ip address #{dhcp_ip}")

    log("Waiting until #{hostdisplayname} is ready")
    ASM::Util.block_and_retry_until_ready(timeout, CommandException, 150) do
      esx_command =  "system uuid get"
      cmd = "esxcli --server=#{static_ip} --username=root --password=#{password} #{esx_command}"
      log("Checking for #{hostdisplayname} ESXi uuid on #{static_ip}")
      results = ASM::Util.run_command_simple(cmd)
      unless results['exit_status'] == 0 and results['stdout'] =~ /[1-9a-z-]+/
        raise(CommandException, results['stderr'])
      end
    end

    # Still cases where ESXi is not available to be added to the cluster
    # in the process_cluster method even after the uuid has been
    # obtained above; trying a 5 minute sleep... Seems to happen more
    # frequently when only one ESXi host is in the deployment.
    sleep(300)

    log("ESXi server #{hostname} is available")
  end

  #
  # This method was added so that we can easily mock out
  # the related components for testing
  #
  def set_components_by_type(type, components)
    @components_by_type ||= {}
    @components_by_type[type] = components
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
        "http://localhost:8081/api/collections/#{type}/#{name}"
        )
      else
        response = RestClient.get(
        "http://localhost:8081/api/collections/#{type}"
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
    server_vlan_info        = {}
    tagged_vlaninfo         = []
    tagged_workloadvlaninfo = []
    untagged_vlaninfo       = []
    server_conf = ASM::Util.build_component_configuration(server_component, :decrypt => decrypt?)
    network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
    if network_params
      [ 'hypervisor_network', 'converged_network', 'vmotion_network',
        'private_cluster_network', 'live_migration_network'
      ].each do |net|
        if  network_params[net]
          networks = network_params[net]
          raise(Exception, "Exactly one #{net} expected") unless networks.size == 1
          vlan = networks[0]['vlanId'].to_s
          logger.debug "#{net} :: #{vlan}"
          tagged_vlaninfo.push(vlan)
        end
      end

      if network_params['storage_network']
        networks = network_params['storage_network']
        raise(Exception, 'Exactly two storage networks expected') unless networks.size == 2
        iscsivlanid = networks[0]['vlanId']
        raise(Exception, 'iSCSI vlan ids must be the same') unless iscsivlanid == networks[1]['vlanId']
        tagged_vlaninfo.push(iscsivlanid.to_s)
      end

      if network_params['workload_network']
        networks = network_params['workload_network']
        networks.each do |network|
          tagged_workloadvlaninfo.push(network['vlanId'])
        end
      end

      if network_params['pxe_network']
        networks = network_params['pxe_network']
        raise(Exception, "Exactly one pxe network expected, found #{network_params['pxe_network'].inspect}") unless networks.size == 1
        pxevlanid = networks[0]['vlanId']
        untagged_vlaninfo.push(pxevlanid.to_s)
      end

      logger.debug "Tagged vlan info #{tagged_vlaninfo}"
      logger.debug "Untagged vlan info #{untagged_vlaninfo}"
      server_vlan_info["#{server_cert}_taggedvlanlist"] = tagged_vlaninfo
      server_vlan_info["#{server_cert}_taggedworkloadvlanlist"] = tagged_workloadvlaninfo
      server_vlan_info["#{server_cert}_untaggedvlanlist"] = untagged_vlaninfo
      logger.debug "Server vlan hash is #{server_vlan_info}"
    else
      log("Did not find expected class asm::iscsiconfig")
    end
    return server_vlan_info
  end

  def initiate_discovery(device_hash)
    if !device_hash.empty?
      discovery_obj = Discoverswitch.new(device_hash)
      discovery_obj.discoverswitch(logger)
    end
  end

  def compellent_in_service_template()
    found=false
    (@components_by_type['STORAGE'] || []).each do |storage_component|
      storage_cert_name = storage_component['puppetCertName']
      if storage_cert_name.downcase.match(/compellent/)
        found=true
        break
      end
    end
    found
  end

  def compellent_controller_ids()
    controller_info={}

    (@components_by_type['STORAGE'] || []).each do |storage_component|
      storage_cert_name = storage_component['puppetCertName']
      if (storage_cert_name.downcase.match(/compellent/) != nil)
        asm_guid=storage_component['asmGUID']
        logger.debug"Getting the compellent facts"
        controller_info=ASM::Util.find_compellent_controller_info(asm_guid)
        break
      end
    end
    controller_info
  end

  def get_compellent_san_information()
    #    saninformation={
    #      'configure_san_switch' => true,
    #    }
    configure_san_switch=true
    (@components_by_type['STORAGE'] || []).each do |storage_component|
      logger.debug"Storage component: #{storage_component.inspect}"
      storage_cert_name = storage_component['puppetCertName']
      logger.debug"Storage cert name: #{storage_cert_name}"
      if (storage_cert_name.downcase.match(/compellent/) != nil)
        resources = ASM::Util.asm_json_array(storage_component['resources']) || []
        resources.each do |resource|
          parameters=ASM::Util.asm_json_array(resource['parameters']) || []
          logger.debug"Resource info #{resource.inspect}"
          parameters.each do |param|
            if param['id'] == "configuresan"
              logger.debug "Setting configure_san_switch to #{param['id']}"
              configure_san_switch=param['value']
              break
            end
          end
        end
      end
    end
    saninformation={
      'configure_san_switch' => configure_san_switch,
    }
  end

  def reboot_all_servers
    reboot_count = 0
    (@components_by_type['SERVER'] || []).each do |server_component|
      server_cert_name = server_component['puppetCertName']
      deviceconf ||= ASM::Util.parse_device_config(server_cert_name)
      # Get the powerstate, if the powerstate is 13, the reboot the server
      power_state = ASM::WsMan.get_power_state(deviceconf, logger)
      logger.debug "Current power state of server #{server_cert_name} is #{power_state}"
      if power_state == "13"
        logger.debug("Rebooting the server #{server_cert_name}")
        ASM::WsMan.reboot(deviceconf, logger)
        reboot_count +=1
      end
    end
    if reboot_count > 0
      logger.debug "Some servers are rebooted, need to sleep for a minute"
      # Adding additional delay to take care of Brocade 5424 SAN IOM module
      sleep(300)
    else
      logger.debug "No server is rebooted, no need to sleep"
    end
  end

  def servers_has_fc_enabled()
    returncode=true
    returnmessage=""
    (@components_by_type['SERVER'] || []).each do |server_component|
      server_cert_name = server_component['puppetCertName']
      wwpns ||= (get_specific_dell_server_wwpns(server_component) || [])
      if wwpns.nil? or (wwpns.length == 0)
        returnmessage += "\n Server #{server_cert_name} do not have any WWPN in the inventory"
        logger.debug "Server #{server_cert_name} do not have any WWPN in the inventory"
        returncode=false
      else
        logger.debug "WWPNs from the WSMAN command: #{wwpns}"
      end
    end
    response={'returncode' => returncode,
      'returnmessage' => returnmessage
    }
  end

  def get_compellent_lunid(hostip, username, password, compellent_deviceid)
    log("getting storage core path information for #{hostip}")
    endpoint = {
      :host => hostip,
      :user => username,
      :password => password,
    }

    cmd = 'storage core path list'.split
    storage_path = ASM::Util.esxcli(cmd, endpoint, logger, true)
    storage_info = storage_path.scan(/Device:\s+naa.#{compellent_deviceid}.*?LUN:\s+(\d+)/m)
    if storage_info.empty?
      msg = "Compellent lunid not found for hostip = #{hostip}, deviceid = #{compellent_deviceid}"
      logger.error(msg)
      raise(Exception, msg)
    end
    storage_info[0][0]
  end

  def configure_hyperv_cluster(component, cluster_resource_hash,title)

    cert_name = component['puppetCertName']
    # Get all the hyperV hosts
    hyperv_hosts = find_related_components('SERVER', component)
    if hyperv_hosts.size == 0
      logger.debug("No HyperV hosts in the template, skipping cluster configuration")
      return true
    end

    hyperv_hostnames = get_hyperv_server_hostnames(hyperv_hosts)
    logger.debug "HyperV Host's hostname: #{hyperv_hostnames}"

    # Run-As-Account
    run_as_account_credentials = run_as_account_credentials(hyperv_hosts[0])
    logger.debug("Run-As Accounf credentials: #{run_as_account_credentials}")
    host_group = cluster_resource_hash['asm::cluster::scvmm'][title]['path']

    logger.debug "Host-Group : '#{host_group}'"
    if ( host_group == '__new__')
      logger.debug "New host-group needs to be created"
      host_group = cluster_resource_hash['asm::cluster::scvmm'][title]['hostgroup']
        if !host_group.include?('All Hosts')
          logger.debug "Host-Group value do not contain All Hosts"
          host_group = "All Hosts\\#{host_group}"
        end
    end

    cluster_name = cluster_resource_hash['asm::cluster::scvmm'][title]['name']
    logger.debug "Cluster name: #{cluster_name}"

    # if not then reserve one ip address from the converged net
    cluster_ip_address = cluster_resource_hash['asm::cluster::scvmm'][title]['ipaddress']
    logger.debug "Cluster IP Address in service template: #{cluster_ip_address}"
    if cluster_ip_address.nil?
      cluster_ip_address = get_hyperv_cluster_ip(hyperv_hosts[0])
    end

    domain_username = "#{run_as_account_credentials['domain_name']}\\#{run_as_account_credentials['username']}"
    resource_hash = Hash.new

    host_group_array = Array.new
    deviceconf = ASM::Util.parse_device_config(cert_name)
    resource_hash['asm::cluster::scvmm'] = {
      "#{cluster_name}" => {
      'ensure'      => 'present',
      'host_group' => host_group,
      'ipaddress' => cluster_ip_address,
      'hosts' => hyperv_hostnames,
      'username' => domain_username,
      'password' => run_as_account_credentials['password'],
      'run_as_account_name' => run_as_account_credentials['username'],
      'logical_network_hostgroups' => host_group_array.push(host_group),
      'logical_network_subnet_vlans' => get_logical_network_subnet_vlans(hyperv_hosts[0]),
      'fqdn' => run_as_account_credentials['fqdn'],
      'scvmm_server' => cert_name,
      }
    }

    process_generic(cert_name, resource_hash, 'apply')
  end


  def run_as_account_credentials(server_component)
    run_as_account = {}
    resource_hash = ASM::Util.build_component_configuration(server_component, :decrypt => decrypt?)
    if resource_hash['asm::server']
      title = resource_hash['asm::server'].keys[0]
      params = resource_hash['asm::server'][title]
      run_as_account['username'] = params['domain_admin_user']
      run_as_account['password'] = params['domain_admin_password']
      run_as_account['domain_name'] = params['domain_name']
      run_as_account['fqdn'] = params['fqdn']
    end
    run_as_account
  end

  def get_hyperv_server_hostnames(server_components)
    hyperv_host_names = []
    server_components.each do |component|
      cert_name = component['puppetCertName']
      resource_hash = {}
      resource_hash = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)

      if resource_hash['asm::server']
        if resource_hash['asm::server'].size != 1
          msg = "Only one O/S configuration allowed per server; found #{resource_hash['asm::server'].size} for #{serial_number}"
          logger.error(msg)
          raise(Exception, msg)
        end

        title = resource_hash['asm::server'].keys[0]
        params = resource_hash['asm::server'][title]
        os_host_name  = params['os_host_name']
        fqdn  = params['fqdn']
        hyperv_host_names.push("#{os_host_name}.#{fqdn}")
      end
    end
    hyperv_host_names.sort
  end

  def get_hyperv_cluster_ip(component)
    # Need to reserve a IP address from the converged network
    cluster_ip = ''
    cert_name = component['puppetCertName']
    server_conf = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)
    network_params = (server_conf['asm::esxiscsiconfig'] || {})[cert_name]
    if network_params
      [ 'converged_network'].each do |net|
        logger.debug "Network GUID : #{network_params.inspect}"
        if  network_params[net]
          cluster_ip = ASM::Util.reserve_network_ips(network_params[net][0]['id'], 1, @id)
        end
      end
    end
    cluster_ip[0]
  end
  

  def get_logical_network_name(component)
    logical_network_name = ''
    cert_name = component['puppetCertName']
    server_conf = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)
    network_params = (server_conf['asm::esxiscsiconfig'] || {})[cert_name]
    if network_params
      [ 'converged_network'].each do |net|
        logger.debug "Network GUID : #{network_params.inspect}"
        if  network_params[net]
          logical_network_name = network_params[net][0]['name']
        end
      end
    end
    logical_network_name
  end
  
def get_logical_network_subnet_vlans(server_component)
  server_cert=server_component['puppetCertName']
  server_vlan_info        = {}
  logical_network_vlaninfo = []
  server_conf = ASM::Util.build_component_configuration(server_component, :decrypt => decrypt?)
  network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
  if network_params
    [ 'hypervisor_network', 'converged_network', 'vmotion_network',
      'private_cluster_network', 'live_migration_network'
    ].each do |net|
      if  network_params[net]
        networks = network_params[net]
        raise(Exception, "Exactly one #{net} expected") unless networks.size == 1
        vlan = networks[0]['vlanId'].to_s
        logger.debug "#{net} :: #{vlan}"
        #logical_network_vlaninfo.push(vlan)
      end
    end

    if network_params['workload_network']
      networks = network_params['workload_network']
      networks.each do |network|
        logical_network_vlan = {}
        #logical_network_vlaninfo.push(network['vlanId'])
        logical_network_vlan = { 'vlan' => network['vlanId'],
                                 'subnet' => ''
                               }
        #logical_network_vlaninfo.push(vlan)
        logical_network_vlaninfo.push(logical_network_vlan)

      end
    end

    if network_params['pxe_network']
      networks = network_params['pxe_network']
      raise(Exception, "Exactly one pxe network expected, found #{network_params['pxe_network'].inspect}") unless networks.size == 1
      pxevlanid = networks[0]['vlanId']
      logical_network_vlan = {}
      logical_network_vlan = { 'vlan' => pxevlanid,
                                 'subnet' => ''
                               }
        #logical_network_vlaninfo.push(vlan)
        logical_network_vlaninfo.push(logical_network_vlan)

      #logical_network_vlaninfo.push(pxevlanid.to_s)
    end

    logger.debug "Logical Network vlan info #{logical_network_vlaninfo}"
  else
    log("Did not find expected class asm::iscsiconfig")
  end
  logical_network_vlaninfo
end


  #This function gets the related services to a component, and creates the classification data that will be passed to puppet module
  def get_classification_data(component, hostname)
    classes_config = {}
    related_services = find_related_components('SERVICE', component)
    related_services.each { |service|
      service_config = ASM::Util.build_component_configuration(service, :type=>'class', :decrypt=>decrypt?)
      services_added = service_config['class'].keys
      classes_config.merge!(service_config['class'])
      log("Added agent application config for #{services_added.join(', ')} to virtual machine #{hostname}")
    }
    return classes_config
  end

  # Server first in the acending order will have the flag as true
  def get_disk_part_flag(server_component)
    disk_part_flag = false
    server_cert_names = []
    cert_name = server_component['puppetCertName']
    (@components_by_type['SERVER'] || []).each do |server_component|
      server_cert_names.push(server_component['puppetCertName'])
    end
    server_cert_names.compact.uniq.sort
    if (server_cert_names.compact.uniq.sort[0] == cert_name)
      disk_part_flag = true
    end
    disk_part_flag
  end

end
