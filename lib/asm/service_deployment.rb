require 'asm'
require 'asm/util'
require 'asm/network_configuration'
require 'asm/processor/server'
require 'asm/razor'
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
require 'asm/resource'

class ASM::ServiceDeployment

  ESXI_ADMIN_USER = 'root'

  class CommandException < Exception; end

  class SyncException < Exception; end

  class PuppetEventException < Exception; end

  attr_reader :id
  attr_reader :configured_rack_switches
  attr_reader :configured_blade_switches
  attr_reader :configured_brocade_san_switches
  attr_reader :db

  def initialize(id, db)
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
    @db = db
    @supported_os_postinstall = ['vmware_esxi', 'hyperv']
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

  def razor
    @razor ||= ASM::Razor.new(:logger => logger)
  end

  def is_retry=(is_retry)
    @is_retry = is_retry
  end

  def is_retry?
    @is_retry
  end

  def process(service_deployment)
    begin
      
      ASM.logger.info("Deploying #{service_deployment['deploymentName']} with id #{service_deployment['id']}")
      log("Status: Started")
      msg = "Starting deployment #{service_deployment['deploymentName']}"
      log(msg)
      db.create_execution(service_deployment)
      db.log(:info, msg)

      # Write the deployment to filesystem for ease of debugging / reuse
      File.write(
        deployment_file('deployment.json'),
        JSON.pretty_generate(service_deployment, :max_nesting=>25)
      )
      
      hostlist = ASM::DeploymentTeardown.get_deployment_certs(service_deployment)
      dup_servers = hostlist.select{|element| hostlist.count(element) > 1 }
      unless dup_servers.empty?
        msg = "Duplicate host names found in deployment #{dup_servers.inspect}"
        logger.error(msg)
        db.log(:error, msg)
        db.set_status(:error)
        raise(Exception, msg)
      end
      if is_retry?
        hostlist = hostlist - ASM::DeploymentTeardown.get_previous_deployment_certs(service_deployment['id'])
      end
      ds = ASM::Util.check_host_list_against_previous_deployments(hostlist)
      unless ds.empty?
        msg = "The listed hosts are already in use #{ds.inspect}"
        logger.error(msg)
        db.log(:error, msg)
        db.set_status(:error)
        raise(Exception, msg)
      end

      # Will need to access other component types during deployment
      # of a given component type in the future, e.g. VSwitch configuration
      # information is contained in the server component type data
      @components_by_type = components_by_type(service_deployment)
      if service_deployment['migration']
        logger.debug("Processing the service deployment migration")
        @components_for_migration = ASM::ServiceMigrationDeployment.components_for_migration(service_deployment)
        reset_servers(@components_for_migration)
      end
      
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
      if e.class == ASM::UserException
        logger.error(e.to_s)
        db.log(:error, e.to_s)
      end
      backtrace = (e.backtrace || []).join("\n")
      File.write(
          deployment_file('exception.log'),
          "#{e.inspect}\n\n#{backtrace}"
      )
      log("Status: Error")
      db.set_status(:error)
      raise(e)
    ensure
      update_vcenters
    end
    db.log(:info, "Deployment completed")
    db.set_status(:complete)
    log("Status: Completed")
  end

  def process_tor_switches(components=nil)
    # Get all Servers
    components = @components_by_type if components.nil?
    logger.debug("Component in the input list: #{components}")
    (components['SERVER'] || []).each do |server_component|
      server_cert_name =  server_component['puppetCertName']
      logger.debug "Server cert name: #{server_cert_name}"

      if ASM::Util.dell_cert?(server_cert_name)
        # If we got service tag, it is a dell server and we get inventory
        logger.debug("Server CERT NAME IS: #{server_cert_name}")
        inventory = ASM::Util.fetch_server_inventory(server_cert_name)
      else
        inventory = nil
      end

      if inventory
        # Putting the re-direction as per the blade type
        # Blade and RACK server
        blade_type = inventory['serverType'].downcase
        logger.debug("Server Blade type: #{blade_type}")
        if blade_type == "rack"
          logger.debug "Configuring rack server"
          server_vlan_info = get_server_networks_rackserver(server_component,server_cert_name)
          server_nic_type  = get_server_nic_type(server_component,server_cert_name)
          if @configured_rack_switches.length() > 0
            logger.debug "Configuring ToR configuration for server #{server_cert_name}"
            configure_tor(server_cert_name, server_vlan_info,server_nic_type)
          else
            logger.debug "INFO: There are no RACK ToR Switches in the ASM Inventory"
          end
        else
          if @configured_blade_switches.length() > 0
            logger.debug "Configuring blade server"
            server_vlan_info = get_server_networks(server_component,server_cert_name)
            server_nic_type = get_server_nic_type(server_component,server_cert_name)
            configure_tor_blade(server_cert_name, server_vlan_info,server_nic_type)
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
  def process_san_switches(components=nil)

    components = @components_by_type if components.nil?
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

    fcsupport=servers_has_fc_enabled(components)
    if !fcsupport['returncode']
      logger.error(fcsupport['returnmessage'])
      raise(Exception,"#{fcsupport['returnmessage']}")
    end

    # Reboot all servers to ensure that the WWPN values are accessible on the Brocade switch
    reboot_all_servers(components)

    # Initiating the discovery of the Brocade switches so that all the values are updated
    initiate_discovery(@brocade_san_switchhash)

    # Get the compellent controller id's, required for mapping of information
    compellent_contollers=compellent_controller_ids()

    san_hash = {}
    # Perform the SAN configuration for each server
    servers = []
    (components['SERVER'] || []).each do |server_component|
      server_cert_name =  server_component['puppetCertName']
      logger.debug "Server cert name: #{server_cert_name}"

      if ASM::Util.dell_cert?(server_cert_name)
        # If we got service tag, it is a dell server and we get inventory
        logger.debug("Server CERT NAME IS: #{server_cert_name}")
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
        servers.push(server_cert_name) if !servers.include?(server_cert_name)
        san_hash["#{server_cert_name}"] = configure_san_switch(server_cert_name, wwpns, compellent_contollers)
        logger.debug("SAN HASH after merge : #{san_hash}")
      else
        logger.debug "Not able to identify server inventory or wwpn information for server #{server_cert_name}"
      end
    end
    logger.debug("SAN HASH end of loop : #{san_hash}")
    san_info = {}
    if servers.size > 0
      servers.each do |server|
        san_switch_info = san_hash["#{server}"]
        logger.debug "san_switch_info : #{san_switch_info}"
        san_switch_info.each do |switch_cert,swinfo|
          logger.debug "Switch : #{switch_cert} resource_hash: #{swinfo}"
          san_info["#{switch_cert}"] ||= {}
          san_info["#{switch_cert}"] = san_info["#{switch_cert}"].keep_merge(swinfo)
        end
      end
      logger.debug "san_info after translation: #{san_info}"
      san_info.each do |san_switch,resource_hash|
        logger.debug("Process san switch: #{san_switch}")
        logger.debug("SAN Resource hash: #{resource_hash}")
        process_generic(san_switch,resource_hash , 'device', true, san_switch) 
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

  def process_components(components=nil)
    components = @components_by_type if components.nil?
    ['STORAGE', 'TOR', 'SERVER', 'CLUSTER', 'VIRTUALMACHINE', 'TEST'].each do |type|
      if components = @components_by_type[type]
        log("Processing components of type #{type}")
        log("Status: Processing_#{type.downcase}")
        db.log(:info, "Processing #{type.downcase} components")
        components.collect do |comp|
          #
          # TODO: this is some pretty primitive thread management, we need to use
          # something smarter that actually uses a thread pool
          #
          Thread.new do
            raise(Exception, 'Component has no certname') unless comp['puppetCertName']
            Thread.current[:component_id] = comp['id']
            Thread.current[:certname] = comp['puppetCertName']
            Thread.current[:component_name] = comp['name']
            db.set_component_status(comp['id'], :in_progress)
            db.log(:info, "Processing #{comp['name']}", :component_id => comp['id'])
            send("process_#{type.downcase}", comp)
          end
        end.each do |thrd|
          begin
            thrd.join
            log("Status: Completed_component_#{type.downcase}/#{thrd[:certname]}")
            db.log(:info, "#{thrd[:component_name]} deployment complete", :component_id => thrd[:component_id])
            db.set_component_status(thrd[:component_id], :complete)
          rescue Exception => e
            log("Status: Failed_component_#{type.downcase}/#{thrd[:certname]}")
            db.log(:error, "#{thrd[:component_name]} deployment failed", :component_id => thrd[:component_id])
            db.set_component_status(thrd[:component_id], :error)
            raise(e)
          end
        end
        log("Finished components of type #{type}")
        db.log(:info, "Finished processing #{type.downcase} components")
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
          puppet_out = iterate_file(deployment_file("#{cert_name}.out"))
          # synchronize creation of file counter
          resource_file = iterate_file(resource_file)
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
            ASM::Util.run_command_streaming(cmd, puppet_out)
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
  def iterate_file(file)
    if File.exists?(file)
      file_ext = file.split('.').last
      # search for all files that match our pattern, increment us!
      base_name = File.basename(file, ".#{file_ext}")
      dir       = File.dirname(file)
      matching_files = File.join(dir, "#{base_name}___*")
      i = 1
      Dir[matching_files].each do |f|
        f_split   = File.basename(f, ".#{file_ext}").split('___')
        num = Integer(f_split.last)
        i = num > i ? num : i
      end
      file = File.join(dir, "#{base_name}___#{i + 1}.#{file_ext}")
    else
      file
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

    # Use real windows version
    params['os_image_version'] ||= params['os_image_type']

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
        cert_name = comp['puppetCertName']
        if ASM::Util.dell_cert?(cert_name)
          deviceconf = ASM::Util.parse_device_config(cert_name)
          ASM::WsMan.get_wwpns(deviceconf,logger)
        end
      end.compact.flatten.uniq
    end
  end
  
  def get_specific_dell_server_wwpns(comp)
    wwpninfo=nil
    cert_name   = comp['puppetCertName']
    return unless ASM::Util.dell_cert?(cert_name)
    deviceconf = ASM::Util.parse_device_config(cert_name)
    ASM::WsMan.get_wwpns(deviceconf,logger)
  end

  def process_test(component)
    config = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)
    process_generic(component['puppetCertName'], config, 'apply', true)
  end

  def build_network_config(server_comp)
    server = ASM::Util.build_component_configuration(server_comp, :decrypt => decrypt?)
    network_params = server['asm::esxiscsiconfig']
    if network_params && !network_params.empty?
      params = network_params[network_params.keys[0]]
      ASM::NetworkConfiguration.new(params['network_configuration'])
    end
  end

  def build_related_network_configs(comp)
    related_servers = find_related_components('SERVER', comp)
    related_servers.map do |server_comp|
      build_network_config(server_comp)
    end.compact
  end

  def process_storage(component)
    log("Processing storage component: #{component['id']}")

    resource_hash = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)

    process_storage = false
    (resource_hash['compellent::createvol'] || {}).each do |title, params|
      # Check if the volume has boot volume set to true
      related_servers = find_related_components('SERVER', component)
      boot_flag = resource_hash['compellent::createvol'][title]['boot']
      if boot_flag
        # There has to be only one related server, else raise error
        unless related_servers.size == 1
          raise(Exception, "Expected to find only one related server, found #{related_servers.size}")
        end
      end
      configure_san = resource_hash['compellent::createvol'][title]['configuresan']
      resource_hash['compellent::createvol'][title].delete('configuresan')
      resource_hash['compellent::createvol'][title]['force'] = 'true'

      related_servers.each do |server_comp|
        wwpns = nil
        wwpns ||= (get_specific_dell_server_wwpns(server_comp || []))
        new_wwns = wwpns.compact.map {|s| s.gsub(/:/, '')}
        resource_hash['compellent::createvol'][title]['wwn'] = new_wwns
        server_servicetag = ASM::Util.cert2serial(server_comp['puppetCertName'])
        
        vol_size = resource_hash['compellent::createvol'][title]['size']
        if vol_size.nil?
          logger.debug("Processing existing compellent volume")
          resource_hash = ASM::Util.update_compellent_resource_hash(component['puppetCertName'],
            resource_hash,title,logger)
          configure_san = true
        end 

        if configure_san
          resource_hash['compellent::createvol'][title]['servername'] = "ASM_#{server_servicetag}"
        else
          resource_hash['compellent::createvol'][title]['servername'] = ""
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
      process_storage = true
    end

    # Process EqualLogic manifest file in case auth_type is 'iqnip'
    network_configs = build_related_network_configs(component)
    (resource_hash['asm::volume::equallogic'] || {}).each do |title, params|
      if resource_hash['asm::volume::equallogic'][title]['auth_type'] == "iqnip"
        iscsi_ipaddresses = network_configs.map do |network_config|
          ips = network_config.get_static_ips('STORAGE_ISCSI_SAN')
          raise("Expected 2 iscsi interfaces for hyperv, only found #{ips.size}") unless ips.size == 2
          ips
        end.flatten.uniq
        logger.debug "iSCSI IP Address reserved for the deployment: #{iscsi_ipaddresses}"
        server_template_iqnorip = resource_hash['asm::volume::equallogic'][title]['iqnorip']
        logger.debug "server_template_iqnorip : #{server_template_iqnorip}"
        if !server_template_iqnorip.nil?
          logger.debug "Value of IP or IQN provided"
          new_iscsi_iporiqn = server_template_iqnorip.split(',') + iscsi_ipaddresses
        else
          logger.debug "Value of IP or IQN not provided in service template"
          new_iscsi_iporiqn = iscsi_ipaddresses
        end
        new_iscsi_iporiqn = new_iscsi_iporiqn.compact.map {|s| s.gsub(/ /, '')}
        resource_hash['asm::volume::equallogic'][title]['iqnorip'] = new_iscsi_iporiqn
      end
    end

    (resource_hash['netapp::create_nfs_export'] || {}).each do |title, params|
      # TODO: Why is the variable called management_ipaddress if it is a list including nfs ips?
      management_ipaddress = network_configs.map do |network_config|
        # WAS: if name == 'hypervisor_network' or name == 'converged_network' or name == 'nfs_network'
        # TODO: what network type is converged_network?
          network_config.get_static_ips('HYPERVISOR_MANAGEMENT', 'FILESHARE')
      end.flatten.uniq
      logger.debug "NFS IP Address in host processing: #{management_ipaddress}"
      if management_ipaddress.empty?
        management_ipaddress = ['all_hosts'] # TODO: is this a magic value?
        logger.debug "NFS IP Address list is empty: #{management_ipaddress}"
      end
      resource_hash['netapp::create_nfs_export'][title]['readwrite'] = management_ipaddress
      resource_hash['netapp::create_nfs_export'][title]['readonly'] = ''

      size_param = resource_hash['netapp::create_nfs_export'][title]['size']
      if !size_param.nil?
        if size_param.include?('GB')
          resource_hash['netapp::create_nfs_export'][title]['size'] = size_param.gsub(/GB/,'g')
        end
        if size_param.include?('MB')
          resource_hash['netapp::create_nfs_export'][title]['size'] = size_param.gsub(/MB/,'m')
        end
        if size_param.include?('TB')
          resource_hash['netapp::create_nfs_export'][title]['size'] = size_param.gsub(/TB/,'t')
        end
      else
        # default parameter which is not applicable if volume exists
        resource_hash['netapp::create_nfs_export'][title]['size'] = '10g'
      end

      resource_hash['netapp::create_nfs_export'][title].delete('path')
      resource_hash['netapp::create_nfs_export'][title].delete('nfs_network')
      snapresv = resource_hash['netapp::create_nfs_export'][title]['snapresv']
      if !snapresv.nil?
        resource_hash['netapp::create_nfs_export'][title]['snapresv'] = snapresv.to_s
      else
        resource_hash['netapp::create_nfs_export'][title]['snapresv'] = '0'.to_s
        resource_hash['netapp::create_nfs_export'][title]['append_readwrite'] = 'true'
      end

      # handling anon
      resource_hash['netapp::create_nfs_export'][title].delete('anon')
    end

    if !process_storage
      process_generic(
      component['puppetCertName'],
      resource_hash,
      'device',
      true,
      nil,
      component['asmGUID']
      )
    end
  end

  def process_tor(component)
    log("Processing tor component: #{component['puppetCertName']}")
    config = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)
    process_generic(component['puppetCertName'], config, 'device')
  end

  def configure_tor(server_cert_name,server_vlan_info,server_nic_type)
    serverhash = get_server_inventory(server_cert_name) || {}
    logger.debug "******** In process_tor after getServerInventory serverhash is #{ASM::Util.sanitize(serverhash)} **********\n"
    switchinfoobj = Get_switch_information.new()
    switchportdetail = switchinfoobj.get_info(serverhash,@rack_server_switchhash,logger,server_nic_type,server_vlan_info)
    logger.debug "******** In process_tor switchportdetail :: #{switchportdetail} *********\n"
    sinfo = serverhash[ASM::Util.cert2serial(server_cert_name)]
    macArray = sinfo['mac_addresses']
    fabric_interfaces = switchinfoobj.get_fabic_configured_interfaces(server_nic_type,server_vlan_info,macArray,logger)
    logger.debug("Fabric Interface: #{fabric_interfaces}")

    fabric_enum = []
    ("A".."Z").each_with_index do |char,index|
      fabric_enum[index] = "Fabric #{char}"
    end

    # Need to configure the VLANs Per Card/Per Port instead of per fabric
    server_vlan_info.each do |card,card_info|
      card_info.each do |interface,interface_info|
        tagged_vlans = interface_info['tagged_vlans']
        untagged_vlans = interface_info['untagged_vlans']
        if ((tagged_vlans.nil? or tagged_vlans.length == 0) and ( untagged_vlans.nil? or untagged_vlans.length == 0))
          logger.debug("No tagged / untagged VLANS for card #{card}, port #{interface}")
          next
        end
        resource_hash = Hash.new
        switchportdetail.each do |switchportdetailhash|
          switchportdetailhash.each do |macaddress,intfhash|
            logger.debug "macaddress :: #{macaddress}    intfhash :: #{intfhash}"
            switchcertname = intfhash[0][0]
            interface = intfhash[0][1][0]
            # Check if interface needs to be configured for this fabric
            if macaddress != interface_info['mac_address']
              logger.debug "Interface #{interface} not required to be configured for card #{card}, interface: #{interface}"
              next
            end
            
            interfaces = get_interfaces(interface)
            portchannels = get_portchannel(interface)
            logger.debug "switchcertname :: #{switchcertname} interface :: #{interface}"
            tagged_vlans.each do |vlanid|
              logger.debug "vlanid :: #{vlanid}"
              if switchcertname =~ /dell_ftos/
                switch_resource_type = "asm::force10"
                resource_hash[switch_resource_type] ||= {}
                resource_hash[switch_resource_type]["#{vlanid}"] = {
                  'vlan_name' => '',
                  'desc' => '',
                  'tagged_tengigabitethernet' => interfaces.strip,
                  'tagged_portchannel' => portchannels.strip
                }
                logger.debug("*** resource_hash is #{resource_hash} ******")
              elsif switchcertname =~ /dell_powerconnect/
                switch_resource_type = "asm::powerconnect"
                resource_hash[switch_resource_type] ||= {}
                resource_hash[switch_resource_type]["#{vlanid}"] = {
                  'vlan_name' => '',
                  'portchannel' => portchannels.strip,
                  'interface' => interfaces.strip,
                  'mode' => 'general'
                }
              elsif switchcertname =~ /dell_iom/
                switch_resource_type = "asm::iom"

              else
                logger.debug "Non-supported switch type"
                return
              end
              #process_generic(switchcertname, resource_hash, 'device', true, server_cert_name)
            end
            untagged_vlans.each do |vlanid|
              logger.debug "vlanid :: #{vlanid}"
              if switchcertname =~ /dell_ftos/
                switch_resource_type = "asm::force10"
                resource_hash[switch_resource_type] ||= {}
                resource_hash[switch_resource_type]["#{vlanid}"] = {
                  'vlan_name' => '',
                  'desc' => '',
                  'untagged_tengigabitethernet' => interfaces.strip,
                }
                logger.debug("*** resource_hash is #{resource_hash} ******")
              elsif switchcertname =~ /dell_iom/
                switch_resource_type = "asm::iom"
              else
                logger.debug "Non-supported switch type"
                return
              end
              #process_generic(switchcertname, resource_hash, 'device', true, server_cert_name)
            end
            logger.debug("Switch #{switchcertname}, Resource hash: #{resource_hash}")
            process_generic(switchcertname, resource_hash, 'device', true, server_cert_name)
          end
        end
      end
    end
  end

  def configure_tor_blade(server_cert_name, server_vlan_info,server_nic_type)
    device_conf = nil
    inv = nil
    switchhash = {}
    serverhash = {}
    deviceConfDir ='/etc/puppetlabs/puppet/devices'
    serverhash = get_server_inventory(server_cert_name)
    logger.debug "******** In process_tor after getServerInventory serverhash is #{ASM::Util.sanitize(serverhash)} **********\n"
    switchinfoobj = Get_switch_information.new()
    switchportdetail = switchinfoobj.get_info(serverhash,@blade_server_switchhash,logger,server_nic_type)
    logger.debug "******** In process_tor switchportdetail :: #{switchportdetail} *********\n"

    # Need to process for the ToR Switches for each Fabric
    ["Fabric A", "Fabric B", "Fabric C"].each do |fabric|
      ioaslots = []
      case fabric
      when "Fabric A"
        ioaslots = ["A1", "A2"]
      when "Fabric B"
        ioaslots = ["B1", "B2"]
      when "Fabric C"
        ioaslots = ["C1", "C2"]
      end
      
      
      switchportdetail.each do |switchportdetailhash|
        switchportdetailhash.each do |macaddress,intfhashes|
          resource_hash = Hash.new
          switchcertname = ""
          logger.debug "macaddress :: #{macaddress}, intfhash :: #{intfhashes}"
          logger.debug "IOA Slots to process: #{ioaslots}"
          
          intfhashes.each_with_index do |intfhash,index|
            ioaslot = intfhash[2]
            if !ioaslots.include?(ioaslot)
              next
            end
            
            port_count = index + 1
            vlan_for_port = server_vlan_info[fabric]["Port #{port_count}"]
            tagged_vlans = vlan_for_port['tagged']
            untagged_vlans = vlan_for_port['untagged']
            if tagged_vlans.length == 0 and untagged_vlans == 0
              logger.debug("No VLAN is requested for Fabric #{fabric}, Port #{index}")
            end
            
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
                resource_hash[switch_resource_type] ||= {}
                resource_hash[switch_resource_type]["#{interface}"] = {
                  
                  'vlan_tagged' => tagged_vlans.join(","),
                  'vlan_untagged' => untagged_vlans.join(","),
                  
                }
                logger.debug("*** resource_hash is #{resource_hash} ******")
              end
            elsif iom_type == "mxl"
              match = interface.match(/(\w*)(\d.*)/)
              interface = $2
              tagged_vlans.each do |vlanid|
                logger.debug "vlanid :: #{vlanid}"
                if switchcertname =~ /dell_iom/
                  switch_resource_type = "asm::mxl"
                  resource_hash[switch_resource_type] ||= {}
                  resource_hash[switch_resource_type]["#{vlanid}"] = {
                    'vlan_name' => '',
                    'tagged_tengigabitethernet' => interface,
                    'tagged_portchannel' => ''
                  }
                  logger.debug("*** resource_hash is #{resource_hash} ******")
                end
              end # end of tagged vlan loop

              logger.debug "Configuring un-tagged vlans"
              untagged_vlans.each do |vlanid|
                logger.debug "vlanid :: #{vlanid}"
                if switchcertname =~ /dell_iom/
                  switch_resource_type = "asm::mxl"
                  resource_hash[switch_resource_type] ||= {}
                  resource_hash[switch_resource_type]["#{vlanid}"] = {
                    'vlan_name' => '',
                    'untagged_tengigabitethernet' => interface,
                    'tagged_portchannel' => '',
                  }
                  logger.debug("*** resource_hash is #{resource_hash} ******")
                end
              end
            else
              logger.debug "Non supported IOA type #{iom_type}"
            end
            logger.debug("final resource_hash for switch #{switchcertname} is #{resource_hash} ******")
            process_generic(switchcertname, resource_hash, 'device', true, server_cert_name)
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

    san_switches = []
    san_switch_resource = {}
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
        switch_active_zoneset="ASM_Zoneset"
      else
        switch_active_zoneset=switch_info[2]
      end

      switch_storage_alias=switch_info[3]
      logger.debug"switch_active_zoneset: #{switch_active_zoneset}"
      logger.debug"switch_storage_alias:#{switch_storage_alias}"

      service_tag=ASM::Util.cert2serial(server_cert_name)
      zone_name="ASM_#{service_tag}"

      certname_to_var = certname_to_var(switchcertname)
      if !san_switches.include?(switchcertname)
        san_switches.push(switchcertname) 
        self.instance_variable_set("@resource_hash_#{certname_to_var}",Hash.new)
      end
      
      self.instance_variable_get("@resource_hash_#{certname_to_var}")["brocade::createzone"] ||= {}
      self.instance_variable_get("@resource_hash_#{certname_to_var}")["brocade::createzone"]["#{zone_name}"] = {
        'storage_alias' => switch_storage_alias,
        'server_wwn' => server_wwpn,
        'zoneset' => switch_active_zoneset
      }
    end
    
    logger.debug("SAN Switch name : #{san_switches}" )
    san_switches.each do |san_switch|
      #switch_var = "resource_hash_#{san_switch}"
      certname_to_var = certname_to_var(san_switch)
      resource_hash = self.instance_variable_get("@resource_hash_#{certname_to_var}")
      logger.debug "Resource hash for switch #{san_switch}: #{resource_hash}"
      #process_generic(san_switch, resource_hash, 'device', true, server_cert_name)
      san_switch_resource["#{san_switch}"] = resource_hash 
    end 
    san_switch_resource
  end
  
  def certname_to_var(certname)
    certname.gsub(/\./,'').gsub(/-/,'')
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

  def get_server_inventory(certname)
    serverhash = {}
    serverpropertyhash = {}
    serverpropertyhash = Hash.new
    puts "******** In getServerInventory certname is #{certname} **********\n"
    resourcehash = {}
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

    serverpropertyhash['mac_addresses'] = ASM::WsMan.get_mac_addresses(device_conf, logger)
    logger.debug "******* In getServerInventory server property hash is #{ASM::Util.sanitize(serverpropertyhash)} ***********\n"
    serverhash["#{servicetag}"] = serverpropertyhash
    logger.debug "********* In getServerInventory server Hash is #{ASM::Util.sanitize(serverhash)}**************\n"
    return serverhash
  end

  def get_all_switches()
    #certs = ASM::Util.get_puppet_certs
    
    # Ignore the certs which are not in the managed device list
    managed_devices = ASM::Util.fetch_managed_inventory()
    certs = []
    managed_devices.each do |managed_device|
      certs.push(managed_device['refId']) if managed_device['deviceType'] == "dellswitch"
    end
    
    @configured_rack_switches = certs.find_all do |x|
      x.start_with?('dell_ftos') or x.start_with?('dell_powerconnect')
    end
    @configured_blade_switches = certs.find_all do |x|
      x.start_with?('dell_iom')
    end
    @configured_brocade_san_switches = certs.find_all do |x| 
      x.start_with?('brocade_')
    end
    logger.debug "Rack ToR Switch certificate name list is #{@configured_rack_switches}"
    logger.debug "Blade IOM Switch certificate name list is #{@configured_blade_switches}"
    logger.debug "Brocade SAN Switches certificate name list is #{@configured_brocade_san_switches}"
  end

  def process_switch(type)
    switchhash = {}
    switches = instance_variable_get("@configured_#{type}_switches") || []
    switches.each do |certname|
      logger.debug "***** certname :: #{certname} *****\n"
      conf = {}
      device_conf = ASM::Util.parse_device_config(certname)
      next unless device_conf
      logger.debug "*****  #{ASM::Util.sanitize(device_conf)} *****\n"
      url = device_conf['url']
      logger.debug "Top of Rack URL:: #{url}\n"
      conf['connection_url'] = url
      yield certname, conf
      logger.debug "********* switch property hash is #{conf} *************\n"
      switchhash[certname] = conf
      logger.debug "********* switch hash is #{switchhash} *************\n"
    end
    switchhash
  end

  def populate_rack_switch_hash
    process_switch('rack') do |certname, conf|
      if certname =~ /dell_ftos/
        conf['device_type'] = "dell_ftos"
      else
        conf['device_type'] = "dell_powerconnect"
      end
    end
  end

  def populate_brocade_san_switch_hash
    process_switch('brocade_san') do |certname, conf|
      if certname =~ /brocade_fos/
        conf['device_type'] = "brocade_fos"
      else
        logger.debug "non-supported switch type #{certname}"
        next
      end
    end
  end

  def populate_blade_switch_hash
    process_switch('blade') do |certname, conf|
      if certname =~ /dell_ftos/
        conf['device_type'] = "dell_ftos"
      else
        conf['device_type'] = "dell_powerconnect"
      end
    end
  end

  def process_server(component)
    log("Processing server component: #{component['puppetCertName']}")
    cert_name = component['puppetCertName']

    # In the case of Dell servers the cert_name should contain
    # the service tag and we retrieve it here
    serial_number = ASM::Util.cert2serial(cert_name)
    is_dell_server = ASM::Util.dell_cert?(cert_name)
    logger.debug "#{cert_name} -> #{serial_number}"
    logger.debug "Is #{cert_name} a dell server? #{is_dell_server}"
    resource_hash = {}
    server_vlan_info = {}
    deviceconf = nil
    inventory = nil
    os_host_name = nil
    resource_hash = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)
    if !is_dell_server && resource_hash['asm::idrac']
      logger.debug "ASM-1588: Non-Dell server has an asm::idrac resource"
      logger.debug "ASM-1588: Stripping it out."
      resource_hash.delete('asm::idrac')
    end

    #Flag an iSCSI boot from san deployment
    target_boot_device = resource_hash['asm::idrac'][resource_hash['asm::idrac'].keys[0]]['target_boot_device'] if is_dell_server
    if is_dell_server and  (target_boot_device == 'iSCSI' or target_boot_device == 'FC')
      @bfs = true
    else
      @bfs = false
    end

    if resource_hash['asm::server'] and !@bfs 
      if resource_hash['asm::server'].size != 1
        msg = "Only one O/S configuration allowed per server; found #{resource_hash['asm::server'].size} for #{serial_number}"
        logger.error(msg)
        raise(Exception, msg)
      end

      server = ASM::Resource::Server.create(resource_hash).first
     
      title = server.title
      os_image_type = server.os_image_type
      os_host_name = server.os_host_name
      os_image_version = server.os_image_version

      params = resource_hash['asm::server'][title]
      classes_config = get_classification_data(component, os_host_name)
      server.process!(serial_number, rule_number, @id, classes_config)

      if kickstart_script = server.delete('custom_script')
        custom_script_path = create_custom_script(serial_number, kickstart_script.strip)
        server.custom_script = custom_script_path
      end

      #massage_asm_server_params(serial_number, params, classes_config)

      resource_hash['asm::server'] = server.to_puppet
    end

    # Create a vmware ks.cfg include file containing esxcli command line
    # calls to create a static management network that will be executed
    # from the vmware ks.cfg
    static_ip = nil
    network_config = nil
    if resource_hash['asm::esxiscsiconfig'] and !@bfs
      if resource_hash['asm::esxiscsiconfig'].size != 1
        msg = "Only one ESXi networking configuration allowed per server; found #{resource_hash['asm::esxiscsiconfig'].size} for #{serial_number}"
        logger.error(msg)
        raise(Exception, msg)
      end

      title = resource_hash['asm::esxiscsiconfig'].keys[0]
      network_params = resource_hash['asm::esxiscsiconfig'][title]
      network_config = ASM::NetworkConfiguration.new(network_params['network_configuration'], logger)
      if os_image_type.downcase == "vmware_esxi"
        mgmt_network = network_config.get_network('HYPERVISOR_MANAGEMENT')
        static = mgmt_network['staticNetworkConfiguration']
        unless static
          # This should have already been checked previously
          msg = "Static network is required for hypervisor network"
          logger.error(msg)
          raise(Exception, msg)
        end

        static_ip = static['ipAddress']
        content = "network --bootproto=static --device=vmnic0 --ip=#{static_ip}  --netmask=#{static['subnet']} --gateway=#{static['gateway']}"
        # NOTE: vlanId is a FixNum
        if mgmt_network['vlanId']
          content += " --vlanid=#{mgmt_network['vlanId']}"
        end
        nameservers = [static['dns1'], static['dns2']].select { |x| !x.nil? && !x.empty? }
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
          'path' => "/opt/razor-server/tasks/vmware_esxi/bootproto_#{serial_number}.inc.erb",
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
      params['force_reboot'] = !is_retry?
      if network_config
        params['network_configuration'] = network_config.to_hash
      end
      params['before'] = []

      #Process a BFS Server Component
      if params['target_boot_device'] == 'iSCSI'
        logger.debug "Processing iSCSI Boot From San configuration"
        #Flag Server Component as BFS
        @bfs = true          	                              				
        #Get Network Configuration
        params['network_configuration'] = build_network_config(component).to_hash
        #Find first related storage component
        storage_component = find_related_components('STORAGE',component)[0]
        #Identify Boot Volume
        boot_volume = storage_component['resources'].detect{|r|r['id']=='asm::volume::equallogic'}['parameters'].detect{|p|p['id']=='title'}['value']
        #Get Storage Facts
        ASM::Util.run_puppet_device!(storage_component['puppetCertName'])
        params['target_iscsi'] = ASM::Util.find_equallogic_iscsi_volume(storage_component['asmGUID'],boot_volume)['TargetIscsiName']
        params['target_ip'] = ASM::Util.find_equallogic_iscsi_ip(storage_component['puppetCertName'])
      end
    end
    
    if @bfs
      params['network_configuration'] = build_network_config(component).to_hash
      resource_hash.delete("asm::server")
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
      storage_type = 'iscsi'
      iscsi_fabric = 'A'
      target_ip = ''
      storage.each do |c|
        target_devices.push(c['puppetCertName'])
        ASM::Util.asm_json_array(c['resources']).each do |r|
          if r['id'] == 'asm::volume::equallogic'
            r['parameters'].each do |param|
              if param['id'] == 'title'
                vol_names.push(param['value'])
              end
            end
          end
          # For supporting Compellent FC storage access with HyperV deployment
          if r['id'] == 'compellent::createvol'
            storage_type = 'fc'
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
      target_ip = ASM::Util.find_equallogic_iscsi_ip(target_devices.first) if storage_type == 'iscsi'
      iscsi_fabric = get_iscsi_fabric(component,cert_name)[0] if storage_type == 'iscsi'
      
      resource_hash = ASM::Processor::Server.munge_hyperv_server(
                        title,
                        resource_hash,
                        target_ip,
                        vol_names,
                        logger,
                        get_disk_part_flag(component),
                        storage_type,
                        iscsi_fabric
                      )
    end

    # The rest of the asm::esxiscsiconfig is used to configure vswitches
    # and portgroups on the esxi host and is done in the cluster swimlane
    resource_hash.delete('asm::esxiscsiconfig')
    resource_hash.delete('asm::baseserver')
    process_generic(component['puppetCertName'], resource_hash, 'apply', 'true')
    reboot_required = true
    unless @debug || @bfs
      (resource_hash['asm::server'] || []).each do |title, params|
        type = params['os_image_type']
        version = params['os_image_version'] || params['os_image_type']
        hyperv_cert_name = ASM::Util.hostname_to_certname(params['os_host_name'])
        if os_image_type == 'hyperv' and is_retry? and ASM::Util.get_puppet_certs.include?(hyperv_cert_name)
          logger.debug("Server #{params['hostname']} is configured correctly.")
          reboot_required = false
        end
        
        begin
          logger.info("Waiting for razor to get reboot event...")
          razor.block_until_task_complete(serial_number, params['policy_name'], version, :bind)
        rescue          
          logger.info("Server never rebooted.  An old OS may be installed.  Manually rebooting to kick off razor install...")
          ASM::WsMan.reboot({:host=>deviceconf['host'], :user=>deviceconf['user'], :password=>deviceconf['password']}) if reboot_required
        end
        node = razor.block_until_task_complete(serial_number,
                                               params['policy_name'], version)
        if type == 'vmware_esxi'
          raise(Exception, "Static management IP address was not specified for #{serial_number}") unless static_ip
          block_until_esxi_ready(title, params, static_ip, timeout = 900)
        else
          # for retry case, if the agent is already there, no need to wait again for this step
          if reboot_required
            logger.debug("Non HyperV deployment which already exists")
            deployment_status = await_agent_run_completion(ASM::Util.hostname_to_certname(os_host_name), timeout = 3600)
          else
            logger.debug("HyperV deployment for retry case and server already exists. Skipping wait for agent check")
            deployment_status = nil
          end
          if (deployment_status and os_image_type == 'hyperv')
             hyperv_post_installation(ASM::Util.hostname_to_certname(os_host_name), cert_name, timeout=3600)
          end
        end
      end
    end
    update_inventory_through_controller(component['asmGUID'])
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
    related_hash = component['relatedComponents']
    all = (@components_by_type[type] || [])
    all.select { |component| related_hash.keys.include?(component['id']) }
  end

  VSWITCH_TYPES = [ :management, :migration, :workload, :storage ]

  def build_portgroup(vswitch, path, hostip, portgroup_name, network,
    portgrouptype, active_nics, network_type)
    ret = {
      'name' => "#{hostip}:#{portgroup_name}",
      'ensure' => 'present',
      'portgrouptype' => portgrouptype,
      'overridefailoverorder' => 'disabled',
      'failback' => true,
      'mtu' => network_type == :storage ? 9000 : 1500,
      'overridefailoverorder' => 'enabled',
      'nicorderpolicy' => {
      'activenic' => active_nics,
      'standbynic' => [],
      },
      'overridecheckbeacon' => 'enabled',
      'checkbeacon' => false,
      'traffic_shaping_policy' => 'disabled',
      'averagebandwidth' => 1000,
      'peakbandwidth' => 1000,
      'burstsize' => 1024,
      'vswitch' => vswitch,
      'vmotion' => network_type == :migration ? 'enabled' : 'disabled',
      'path' => path,
      'host' => hostip,
      'vlanid' => network['vlanId'],
      'transport' => 'Transport[vcenter]'
    }
  end

  def vswitch_name(vswitch_type)
    "vSwitch#{VSWITCH_TYPES.find_index(vswitch_type)}"
  end

  def build_vswitch(type, vmnics, networks, hostip, params)
    vswitch_name = vswitch_name(type)
    path = "/#{params['datacenter']}/#{params['cluster']}"

    ret = { 'esx_vswitch' => {}, 'esx_portgroup' => {}, }
    vswitch_title = "#{hostip}:#{vswitch_name}"
    ret['esx_vswitch'][vswitch_title] = {
      'ensure' => 'present',
      'num_ports' => 1024,
      'nics' => vmnics,
      'nicorderpolicy' => {
      'activenic' => vmnics,
      'standbynic' => [],
      },
      'path' => path,
      'mtu' => type == :storage ? 9000 : 1500,
      'checkbeacon' => false,
      'transport' => 'Transport[vcenter]',
    }

    next_require = "Esx_vswitch[#{hostip}:#{vswitch_name}]"

    portgrouptype = type == :workload ? 'VirtualMachine' : 'VMkernel'
    is_iscsi = type == :storage && networks.first.type == 'STORAGE_ISCSI_SAN'
    portgroup_names = if type == :storage && is_iscsi
      # iSCSI network
      # NOTE: We have to make sure the ISCSI1 requires ISCSI0 so that
      # they are created in the "right" order -- the order that will
      # give ISCSI0 vmk2 and ISCSI1 vmk3 vmknics. The datastore
      # configuration relies on that.
      raise(Exception, 'Exactly two networks expected for storage network') unless networks.size == 2
      ['ISCSI0', 'ISCSI1']
    elsif type == :management
      # Hypervisor network. Currently the static management ip is
      # set in the esxi kickstart and has a name of "Management
      # Network". We have to match that name in order to be able to
      # change the settings for that portgroup since they are
      # configured by name.
      raise(Exception, 'Exactly one networks expected for management network') unless networks.size == 1
      ['Management Network']
    else
      networks.map { |network| network['name'] }
    end

    portgroup_names.each_with_index do |portgroup_name, index|
      network = networks[index]
      portgroup_title = "#{hostip}:#{portgroup_name}"
      active_nics = is_iscsi ? [vmnics[index]] : vmnics
      portgroup = build_portgroup(vswitch_name, path, hostip, portgroup_name,
                                  network, portgrouptype, active_nics, type)

      if (static = network['staticNetworkConfiguration']) && !static.empty?
        ip = static['ipAddress'] || raise(Exception, "ipAddress not set")
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
    ha_clusters = []
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
      if ASM::Util.to_boolean params['ha_config'] 
        ha_clusters.push "#{params['datacenter']}/#{params['cluster']}"
      end

      # Add ESXi hosts and creds as separte resources
      (find_related_components('SERVER', component) || []).each do |server_component|
        server_conf = ASM::Util.build_component_configuration(server_component, :decrypt => decrypt?)

        (server_conf['asm::server'] || []).each do |server_cert, server_params|
          if server_params['os_image_type'] == 'vmware_esxi'
            install_mem = ASM::Util.to_boolean(server_params['esx_mem'])
            serial_number = ASM::Util.cert2serial(server_cert)

            # Determine host IP
            log("Finding host ip for serial number #{serial_number}")
            network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
            network_config = ASM::NetworkConfiguration.new(network_params['network_configuration'], logger)
            mgmt_network = network_config.get_network('HYPERVISOR_MANAGEMENT')
            static = mgmt_network['staticNetworkConfiguration']
            static = mgmt_network['staticNetworkConfiguration']
            unless static
              # This should have already been checked previously
              msg = "Static network is required for hypervisor network"
              logger.error(msg)
              raise(Exception, msg)
            end
            hostip = static['ipAddress']


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
              'timeout'  => 90,
              'require' => "Asm::Cluster[#{title}]"
            }

            esx_endpoint = { :host => hostip,
                             :user => ESXI_ADMIN_USER,
                             :password => server_params['admin_password'] }
            if decrypt?
              esx_endpoint[:password] = ASM::Cipher.decrypt_string(esx_endpoint[:password])
            end

            if network_params
              # Add vswitch config to esx host
              resource_hash['asm::vswitch'] ||= {}

              next_require = "Asm::Host[#{server_cert}]"
              host_require = next_require
              storage_network_require = nil
              storage_network_vmk_index = nil
              storage_network_vswitch = nil

              # Each ESXi host will implicitly have a Management Network
              # on vmk0. Other VMkernel portgroups that we add will enumerate
              # from there.
              vmk_index = 0

              # TODO: append_resources! should do this automatically
              network_config = ASM::NetworkConfiguration.new(network_params['network_configuration'], logger)
              network_config.cards.each do |card|
                logger.debug("Found card: #{card.name}")
                card.interfaces.each do |port|
                  logger.debug("Found interface: #{port.name}")
                  port.partitions.each do |partition|
                    logger.debug("Found partition: #{partition.name} #{partition.fqdd} #{partition.mac_address} #{partition.networkObjects}")
                  end
                end
              end

              vswitches = get_vmnics_and_networks(esx_endpoint, serverdeviceconf, network_config, network_params)
              vswitches.keys.each do |vswitch_type|
                vswitch = vswitches[vswitch_type]
                vswitch_resources = build_vswitch(vswitch_type, vswitch[:vmnics], vswitch[:networks], hostip, params)
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
                  if portgroup['portgrouptype'] == 'VMkernel' && vswitch_type != :management
                    vmk_index += 1
                  end

                  if vswitch_type == :storage
                    storage_network_require ||= []
                    storage_network_vmk_index ||= vmk_index
                    storage_network_require.push("Esx_portgroup[#{title}]")
                    storage_network_vswitch = vswitch_title
                  end

                end

                # merge these in
                resource_hash['esx_vswitch'] = (resource_hash['esx_vswitch'] || {}).merge(vswitch_resources['esx_vswitch'])
                resource_hash['esx_portgroup'] = (resource_hash['esx_portgroup'] || {}).merge(vswitch_resources['esx_portgroup'])
              end

              logger.debug('Configuring the storage manifest')
              storage_titles = Array.new # we will store storage_titles here - esx_syslog requires one

              (find_related_components('STORAGE', server_component) || []).each do |storage_component|
                storage_cert = storage_component['puppetCertName']
                storage_creds = ASM::Util.parse_device_config(storage_cert)
                storage_hash = ASM::Util.build_component_configuration(storage_component, :decrypt => decrypt?)

                if storage_hash['asm::volume::equallogic']
                  # Configure iscsi datastore
                  if @debug
                    hba_list = [ 'vmhba33', 'vmhba34' ]
                  else
                    hba_list = parse_hbas(esx_endpoint)
                  end
                  raise(Exception, "Network not setup for #{server_cert}") unless storage_network_vmk_index

                  storage_hash['asm::volume::equallogic'].each do |storage_title, storage_params|

                    storage_titles.push storage_title
                    asm_datastore = {
                      'data_center' => params['datacenter'],
                      'cluster' => params['cluster'],
                      'datastore' => storage_title,
                      'ensure' => 'present',
                      'esxhost' => hostip,
                      'esxusername' => 'root',
                      'esxpassword' => server_params['admin_password'],
                      'hba1' => hba_list[0],
                      'hba2' => hba_list[1],
                      'iscsi_target_ip' => ASM::Util.find_equallogic_iscsi_ip(storage_cert),
                      'vmknics' => "vmk#{storage_network_vmk_index}",
                      'vmknics1' => "vmk#{storage_network_vmk_index + 1}",
                      'decrypt' => decrypt?,
                      'require' => storage_network_require,
                    }
                    # We are not using IQN auth? Then add chapname and chapsecret
                    if storage_params.has_key? 'chap_user_name' and not storage_params['chap_user_name'].empty?
                      chap = {
                        'chapname' => storage_params['chap_user_name'],
                        'chapsecret' => storage_params['passwd']}
                      asm_datastore.merge! chap
                    end
                    resource_hash['asm::datastore'] ||= {}
                    resource_hash['asm::datastore']["#{hostip}:#{storage_title}:datastore"] = asm_datastore

                    # HACK: process_generic kicks off asynchronous device
                    # re-inventory through the java REST services. We expect that
                    # would be complete by the time we get here. BUT, java side
                    # uses asmGUID as the puppet certificate name, so we have to
                    # use that here.
                    target_iqn = ASM::Util.get_eql_volume_iqn(storage_component['asmGUID'], storage_title)
                    raise(Exception,"Unable to find the IQN for volume #{storage_title}") if target_iqn.length == 0

                    resource_hash['esx_datastore'] ||= {}
                    resource_hash['esx_datastore']["#{hostip}:#{storage_title}"] ={
                      'ensure' => 'present',
                      'datastore' => storage_title,
                      'type' => 'vmfs',
                      'target_iqn' => target_iqn,
                      'require' => "Asm::Datastore[#{hostip}:#{storage_title}:datastore]",
                      'transport' => 'Transport[vcenter]'
                    }

                    # Esx_mem configuration is below
                    if install_mem
                      vnics = resource_hash['esx_vswitch']["#{storage_network_vswitch}"]['nics'].map do|n|
                        n.strip
                      end

                      vnics_ipaddress = ['ISCSI0', 'ISCSI1'].map do |port|
                        resource_hash['esx_portgroup']["#{hostip}:#{port}"]['ipaddress'].strip
                      end

                      vnics_ipaddress = vnics_ipaddress.join(',')
                      vnics = vnics.join(',')

                      logger.debug "Server params: #{server_params}"
                      esx_mem = {
                        'require'                => [
                          "Esx_datastore[#{hostip}:#{storage_title}]",
                          "Esx_syslog[#{hostip}]"],
                        'install_mem'            => true,
                        'script_executable_path' => '/opt/Dell/scripts/EquallogicMEM',
                        'setup_script_filepath'  => 'setup.pl',
                        'host_username'          => ESXI_ADMIN_USER,
                        'host_password'          => server_params['admin_password'],
                        'transport'              => "Transport[vcenter]",
                        'storage_groupip'        => ASM::Util.find_equallogic_iscsi_ip(storage_cert),
                        'iscsi_netmask'          => ASM::Util.find_equallogic_iscsi_netmask(storage_cert),
                        'iscsi_vswitch'          => storage_network_vswitch,
                        'vnics'                  => vnics,
                        'vnics_ipaddress'        => vnics_ipaddress
                      }
#                      if storage_params.has_key? 'chap_user_name' and not storage_params['chap_user_name'].empty?
#                        chap = {
#                          'iscsi_chapuser'         => storage_params['chap_user_name'],
#                          'iscsi_chapsecret'       => storage_params['passwd'] }
#                        esx_mem.merge! chap
#                      end
                      resource_hash['esx_mem'] ||= {}
                      resource_hash['esx_mem'][hostip] = esx_mem
                    else # We will set up round robin pathing here
                      resource_hash['esx_iscsi_multiple_path_config'] ||= {}
                      resource_hash['esx_iscsi_multiple_path_config'][hostip] = {
                        'ensure'        => 'present',
                        'host'          => hostip,
                        'policyname'    => 'VMW_PSP_RR',
                        'path'          => "/#{params['datacenter']}/#{params['cluster']}",
                        'transport'     => 'Transport[vcenter]',
                        'require'       => "Esx_datastore[#{hostip}:#{storage_title}]"
                      }
                    end
                  end
                end

                if storage_hash['compellent::createvol']
                  # Configure fiber channel datastore

                  storage_hash['compellent::createvol'].each do |volume, storage_params|
                    storage_titles.push volume
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

                    resource_hash['asm::fcdatastore'] ||= {}
                    resource_hash['asm::fcdatastore']["#{hostip}:#{volume}"] = {
                      'data_center' => params['datacenter'],
                      'datastore' => volume,
                      'cluster' => params['cluster'],
                      'ensure' => 'present',
                      'esxhost' => hostip,
                      'lun' => lun_id,
                      'require' => host_require
                    }
                  end
                end

                # Configure NFS Datastore
                if storage_hash['netapp::create_nfs_export']
                  storage_hash['netapp::create_nfs_export'].each do |volume, storage_params|
                    remote_host = get_netapp_ip()
                    remote_path = "/vol/#{volume}"
                    logger.debug "Remote Path: #{remote_path}"
                    logger.debug "Remote host: #{remote_host}"
                    logger.debug "#{hostip}:#{volume}"
                    resource_hash['asm::nfsdatastore'] ||= {}
                    resource_hash['asm::nfsdatastore']["#{hostip}:#{volume}"] = {
                      'data_center' => params['datacenter'],
                      'datastore' => volume,
                      'cluster' => params['cluster'],
                      'ensure' => 'present',
                      'esxhost' => hostip,
                      'remote_host' => remote_host,
                      'remote_path' => remote_path,
                      'require' => host_require
                    }
                  end
                end

              end
              logger.debug('Configuring persistent storage for logs')
              if not storage_titles.empty?
                syslog_volume = storage_titles[0]
                resource_hash['esx_syslog'] ||= {}
                resource_hash['esx_syslog'][hostip] = {
                  'log_dir_unique' => true,
                  'transport' => 'Transport[vcenter]',
                  'log_dir' => "[#{syslog_volume}] logs"
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
      reconfigure_ha_for_clusters(cert_name, ha_clusters)
    end
  end

  # From the specified network_config, returns a hash of:
  #
  # { vswitch_type => { :vmnics => [vmnicn, ...], :networks => [net1, ...]}}
  def get_vmnics_and_networks(esx_endpoint, server_device_conf, network_config, network_params)
    service_tag = ASM::Util.cert2serial(server_device_conf[:cert_name])
    is_dell_server = ASM::Util.dell_cert?(server_device_conf[:cert_name])

    if is_dell_server
      network_config.add_nics!(server_device_conf)
      logger.info('Configuring Dell server networking...')
      vmnic_info = ASM::Util.esxcli('network nic list'.split, esx_endpoint, logger)
      gather_vswitch_info(network_config) do |vswitch_type, partitions|
        mac_addresses = partitions.collect { |partition| partition.mac_address }
        logger.debug("Found mac addresses for #{vswitch_type} vswitch: #{mac_addresses}")
        vmnics_match = vmnic_info.find_all do |info|
          # NOTE: mac addresses from idrac are upper-case, from esxcli lower-case
          mac_addresses.include?(info['MAC Address'].upcase)
        end
        unless vmnics_match.size == mac_addresses.size
          logger.debug("Only #{vmnics_match} vmnics found for mac addresses #{mac_addresses}")
          msg = "Only found #{vmnics_match.size} ESXi vmnics for server #{serial_number}; " +
              "expected #{mac_addresses.size}. Check your network configuration and retry."
          raise(ASM::UserException, msg)
        end
        vmnics_match.map { |info| info['Name'] }
      end
    else
      logger.info("Configuring generic server networking...")
      # Non-dell server; assume partitions are in vmnic enumeration order
      network_config.add_partition_info!
      gather_vswitch_info(network_config) do |vswitch_type, partitions|
        partitions.map { |p| "vmnic#{p.partition_index}" }
      end
    end
  end

  # TODO: validate that:
  #  - same vmnics aren't used for different network types
  #  - only one type of storage network used
  def gather_vswitch_info(network_config)
    network_types_map = {
        :management => ['HYPERVISOR_MANAGEMENT'],
        :migration => ['HYPERVISOR_MIGRATION'],
        :workload => ['PRIVATE_LAN', 'PUBLIC_LAN'],
        :storage => ['STORAGE_ISCSI_SAN', 'FILESHARE'],
    }
    vswitches = {}
    network_types_map.each do |vswitch_type, network_types|
      partitions = network_config.get_partitions(*network_types)
      logger.debug("Found #{partitions.size} partitions matching #{network_types}")

      unless partitions.empty?
        networks = partitions.collect do |partition|
          partition.networkObjects.reject { |network| network.type == 'PXE' }
        end.uniq.flatten.compact
        logger.debug("Found networks for #{vswitch_type} vswitch: #{networks}")
        if networks && !networks.empty?
          vmnics = yield vswitch_type, partitions
          logger.debug("Found vmnics for #{vswitch_type} vswitch: #{vmnics}")
          vswitches[vswitch_type] = {:networks => networks, :vmnics => vmnics}
        end
      end
    end
    vswitches
  end

  def parse_hbas(endpoint)
    hostip = endpoint[:host]
    log("getting hba information for #{hostip}")
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
    vms = ASM::Resource::VM.create(resource_hash)
    raise(Exception, "Expect one set of VM configuration #{vm.size} configuration recieved.") unless vms.size == 1
    vm = vms.first

    servers = ASM::Resource::Server.create(resource_hash)
    raise(Exception, "Expect zero or one set of Server configuration: #{servers.size} were passed") if servers.size > 1
    server = servers.first

    clusters = (find_related_components('CLUSTER', component) || [])
    cluster = clusters.first || {}
    certname = cluster['puppetCertName']
    raise(Exception, "Expect one cluster for #{certname}: #{clusters.size} was passed") unless clusters.size == 1

    cluster_deviceconf = ASM::Util.parse_device_config(certname)
    cluster_resource = ASM::Util.build_component_configuration(cluster, :decrypt => decrypt?)
    clusters = ASM::Resource::Cluster.create(cluster_resource)
    raise(Exception, "Expected one asm::cluster resource: #{clusters.size} was provided") unless clusters.size == 1
    title, cluster_params = clusters.first.shift
    cluster_params.title = title

    vm.process!(certname, server, cluster_params)
    hostname = vm.hostname || server.os_host_name
    unless hostname
      raise(ArgumentError, 'VM hostname not specified, missing server os_host_name value')
    end

    resource_hash = vm.to_puppet
    vm_resource = resource_hash[resource_hash.keys[0]]
    vm_title = vm_resource.keys[0]

    log("Creating VM #{hostname}")
    certname = "vm-#{hostname.downcase}"
    process_generic(certname, resource_hash, 'apply')

    puppet_classes = get_classification_data(component, hostname)
    if puppet_classes
      agent_cert_name = vm.certname
      config = {agent_cert_name => {'classes' => puppet_classes}}
      puppet_node_yaml(agent_cert_name, config)
    end

    if server
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

      serial_number = @debug ? "vmware_debug_serial_no" : ASM::Util.vm_uuid_to_serial_number(uuid)

      # Get the list of related services to this virtual machine, and combine them into one hash
      # TODO: move the massage_asm_server_params stuff into ASM::Resource::Server
      classes_config = get_classification_data(component, hostname)
      massage_asm_server_params(serial_number, server, classes_config)
      server.title = vm_title # TODO: clean this up
      resource_hash['asm::server'] = server.to_puppet
      process_generic(certname, resource_hash, 'apply')
      unless @debug
        # Unlike in bare-metal installs we only wait for the :boot_install
        # log event in razor. At that point the O/S installer has just been
        # launched, it is not complete. This is done because our VMs have hard
        # disk earlier in the boot order than PXE. Therefore the nodes do not
        # check in with razor at all once they have an O/S laid down on hard
        # disk and we will not see any :boot_local events

        version = server['os_image_version'] || server['os_image_type']
        begin
          razor.block_until_task_complete(serial_number, server['policy_name'], version, :bind)
        rescue
          logger.info("VM was not able to PXE boot.  Resetting VM.")
          vm.reset
        end
        razor.block_until_task_complete(serial_number, server['policy_name'],
                                        version, :boot_install)
      end
    end

    if puppet_classes || server
      # Wait for first agent run to complete
      await_agent_run_completion(vm.certname)
      logger.info("Running puppet on VM #{vm_title} one more time to reconfigure networks.")
      vm_resource[vm_title]['network_interfaces'].delete_if{|item| item['portgroup']=="VM Network"}
      #Rerun one more time to remove PXE network. 
      process_generic(certname, resource_hash, 'apply')
    end
  end

  def puppet_node_yaml(certname, config)
    filename = File.join('/etc/puppetlabs/puppet/node_data', "#{certname}.yaml")
    File.write(filename, config.to_yaml)
  end

  def await_agent_run_completion(certname, timeout = 3600)
    #get the time that this method starts so can check for reports that happen afterwards
    function_start = Time.now


    ASM::Util.block_and_retry_until_ready(timeout, CommandException, 60) do
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
    ASM::Util.block_and_retry_until_ready(timeout, CommandException, 60) do
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
  def block_until_esxi_ready(title, params, static_ip, timeout = 3600)
    serial_num = params['serial_number'] || raise(Exception, "resource #{title} is missing required server attribute admin_password")
    password = params['admin_password'] || raise(Exception, "resource #{title} is missing required server attribute admin_password")
    if decrypt?
      password = ASM::Cipher.decrypt_string(password)
    end
    type = params['os_image_type'] || raise(Exception, "resource #{title} is missing required server attribute os_image_type")
    hostname = params['os_host_name'] || raise(Exception, "resource #{title} is missing required server attribute os_host_name")
    hostdisplayname = "#{serial_num} (#{hostname})"

    log("Waiting until ESXi management services available on #{hostdisplayname}")
    start_time = Time.now
    ASM::Util.block_and_retry_until_ready(timeout, CommandException, 150) do
      esx_command =  "system uuid get"
      cmd = "esxcli --server=#{static_ip} --username=root --password=#{password} #{esx_command}"
      log("Checking for #{hostdisplayname} ESXi uuid on #{static_ip}")
      results = ASM::Util.run_command_simple(cmd)
      unless results['exit_status'] == 0 and results['stdout'] =~ /[1-9a-z-]+/
        raise(CommandException, results['stderr'])
      end
    end

    elapsed = Time.now - start_time
    if elapsed > 60
      # Still cases where ESXi is not available to be added to the cluster
      # in the process_cluster method even after the uuid has been
      # obtained above; trying a 5 minute sleep... Seems to happen more
      # frequently when only one ESXi host is in the deployment.
      #
      # NOTE: Only doing this additional sleep if it appears that the host was
      # not already online when this method was called, e.g. if it took more
      # than 60 seconds to complete.
      sleep_secs = 450
      logger.debug("Sleeping an additional #{sleep_secs} waiting for ESXi host #{hostdisplayname} to come online")
      sleep(sleep_secs)
    end

    log("ESXi server #{hostdisplayname} is available")
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
      create_dir(deployment_dir, true)
      deployment_dir 
    end
  end

  def create_dir(dir, warning=false)
    if File.exists?(dir)
      ASM.logger.warn("Directory already exists: #{dir}") if warning
    else
      FileUtils.mkdir_p(dir)
    end
  end

  def deployment_file(*file)
    File.join(deployment_dir, *file)
  end

  def resources_dir
    dir = deployment_file('resources')
    create_dir(dir)
    dir
  end

  def create_logger
    id_log_file = deployment_file('deployment.log')
    File.open(id_log_file, 'w')
    Logger.new(id_log_file)
  end

  def create_custom_script(cert_name,file_content)
    id_log_file = deployment_file("#{cert_name}.cfg")
    File.write(id_log_file, file_content)
    id_log_file
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
    target_boot_device = ""
    target_boot_device = server_conf['asm::idrac'][server_conf['asm::idrac'].keys[0]]['target_boot_device'] if ASM::Util.dell_cert?(server_cert)

    server = ASM::Resource::Server.create(server_conf).first
    
    title = server.title
    os_image_type = (server.os_image_type || '')
    logger.debug("OS Image type: #{os_image_type}")

    network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
    # get fabric information
    fabric_vlan_info = {}
    if network_params
      network_info = network_params['network_configuration']
      fabrics = network_info['fabrics'].find_all{|fabric| ASM::Util.to_boolean(fabric['enabled'])}
      if fabrics
        fabrics.each do |fabric|
          fabric_name = fabric['name']
          fabric_networks = []
          fabric_interfaces = fabric['interfaces']
          if fabric_interfaces
            fabric_vlan_info[fabric_name] ||= {}
            fabric_interfaces.each do |fabric_interface|
              tagged_vlans = []
              untagged_vlans = []
              interface_name = fabric_interface['name']
              fabric_vlan_info[fabric_name][interface_name] ||= {}
              fabric_interface['partitions'].each do |partition|
                partition_network_object = partition['networkObjects']
                partition_vlan_info = get_vlan_info(partition_network_object,target_boot_device,os_image_type)
                if partition_vlan_info
                  tagged_vlans.concat(partition_vlan_info['tagged'])
                  untagged_vlans.concat(partition_vlan_info['untagged'])
                end
              end
              fabric_vlan_info[fabric_name][interface_name]['tagged'] = tagged_vlans.uniq.compact
              untagged_vlans = untagged_vlans.uniq.compact
              fabric_vlan_info[fabric_name][interface_name]['untagged'] = untagged_vlans
              unless untagged_vlans.size <= 1
                raise(Exception,"Only one untagged vlan is alloweed per port, identified #{untagged_vlans.size}")
              end
            end
          end
        end
      end
      fabric_vlan_info
    end

    logger.debug("Fabric VLAN INFO: #{fabric_vlan_info}")
    fabric_vlan_info
  end

  def get_server_networks_rackserver(server_component,server_cert)
    server_vlan_info        = {}
    tagged_vlaninfo         = []
    tagged_workloadvlaninfo = []
    untagged_vlaninfo       = []
    server_conf = ASM::Util.build_component_configuration(server_component, :decrypt => decrypt?)
    target_boot_device = ""
    target_boot_device = server_conf['asm::idrac'][server_conf['asm::idrac'].keys[0]]['target_boot_device'] if ASM::Util.dell_cert?(server_cert)
    network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
    
    server = ASM::Resource::Server.create(server_conf).first
    title = server.title
    os_image_type = (server.os_image_type || '')
    logger.debug("OS Image type: #{os_image_type}")
    
    # get fabric information
    network_fabric_info = {}
    nc = ASM::NetworkConfiguration.new(network_params['network_configuration'])
    device_conf = ASM::Util.parse_device_config(server_cert)
    options = { :add_partitions => true }
    nc.add_nics!(device_conf, options)
    nc.cards.each do |card|
      logger.debug("Card name: #{card}")
      card.interfaces.each do |interface|
        fabric_networks = []
        tagged_vlans = []
        untagged_vlans = []
        interface_mac = ""
        logger.debug("Interface name: #{interface['name']}")
        interface.partitions.each do |partition|
          if partition.partition_no == 1
            interface_mac = partition.mac_address
          end
          logger.debug("Partition: #{partition}")
          logger.debug("Network Object #{partition['networkObjects']}")
          networks = partition['networkObjects']
          partition_vlan_info = get_vlan_info(partition['networkObjects'],target_boot_device,os_image_type)
          if partition_vlan_info
            tagged_vlans.concat(partition_vlan_info['tagged'])
            untagged_vlans.concat(partition_vlan_info['untagged'])
          end
        end
        network_fabric_info[card['card_index']] ||= {}
        network_fabric_info[card['card_index']][interface['name']] ||= {}
        network_fabric_info[card['card_index']][interface['name']]['tagged_vlans'] = tagged_vlans
        network_fabric_info[card['card_index']][interface['name']]['untagged_vlans'] = untagged_vlans
        network_fabric_info[card['card_index']][interface['name']]['mac_address'] = interface_mac
      end
    end
    logger.debug("network_fabric_info: #{network_fabric_info}")
    network_fabric_info
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

  def reboot_all_servers(components)
    reboot_count = 0
    (components['SERVER'] || []).each do |server_component|
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

  def servers_has_fc_enabled(components=nil)
    returncode=true
    returnmessage=""
    components = @components_by_type if  components.nil?
    (components['SERVER'] || []).each do |server_component|
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

    storage_info = []
    (1..5).each do |counter|
      cmd = 'storage core path list'.split
      storage_path = ASM::Util.esxcli(cmd, endpoint, logger, true)
      storage_info = storage_path.scan(/Device:\s+naa.#{compellent_deviceid}.*?LUN:\s+(\d+)/m)
      if storage_info.empty?
        logger.debug("Attempt:#{counter}: Failed to get storage information")
        sleep(60)
      else
        logger.debug("Got the response in attempt: #{counter}")
        break
      end
    end

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
    host_group = cluster_resource_hash['asm::cluster::scvmm'][title]['hostgroup']
    if !host_group.include?('All Hosts')
      logger.debug "Host-Group value do not contain All Hosts"
      host_group = "All Hosts\\#{host_group}"
    end
    logger.debug "Host-Group : '#{host_group}'"

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

    # TODO: why do we only look at the first host? why only workload and pxe networks?
    # why the empty 'subnet' => '' part of the hash?
    network_config = build_network_config(hyperv_hosts[0])
    raise(Exception, "Could not find network config for #{hyperv_hosts[0]}") unless network_config
    subnet_vlans = network_config.get_networks('PUBLIC_LAN', 'PRIVATE_LAN', 'PXE').collect do |network|
      {'vlan' => network['vlanId'], 'subnet' => ''}
    end

    host_group_array = Array.new
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
      'logical_network_subnet_vlans' => subnet_vlans,
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
    network_config = ASM::NetworkConfiguration.new(network_params['network_configuration'], logger)
    management_network = network_config.get_network('HYPERVISOR_MANAGEMENT')
    cluster_ip = ASM::Util.reserve_network_ips(management_network['id'], 1, @id)
    cluster_ip[0]
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

  def get_netapp_ip()
    netappip = ''
    (@components_by_type['STORAGE'] || []).each do |storage_component|
      storage_cert_name = storage_component['puppetCertName']
      logger.debug"Storage cert name: #{storage_cert_name}"
      if (storage_cert_name.downcase.match(/netapp/) != nil)
        netappip = storage_cert_name.gsub(/^netapp-/,'')
        deviceconf ||= ASM::Util.parse_device_config(storage_cert_name)
        netappip = deviceconf[:host]

        resources = ASM::Util.asm_json_array(storage_component['resources']) || []
        resources.each do |resource|
          parameters=ASM::Util.asm_json_array(resource['parameters']) || []
          logger.debug"Resource info #{resource.inspect}"
          parameters.each do |param|
            if param['id'] == "nfs_network"
              nfsip=param['value']
              netappip = nfsip if !(nfsip.nil? || nfsip.length == 0)
              break
            end
          end
        end
      end
    end
    netappip
  end
  
  def get_fabric_vlan_info(network_fabric_info,target_boot_device)
    fabric_vlan_info = {}
    ["Fabric A", "Fabric B", "Fabric C"].each do |fabric|
      fabric_vlan_info["#{fabric}"] = {}
      if network_fabric_info["#{fabric}"]
        vlan_tagged = []
        vlan_untagged = []
        logger.debug("Processing fabric : #{fabric}")
        network_fabric_info["#{fabric}"].compact.each do |network_info|
          if target_boot_device != "iSCSI"
            if network_info['type'].to_s != "PXE"
              vlan_tagged.push(network_info['vlanId'])
            else
              vlan_untagged.push(network_info['vlanId'])
            end
          else
            if network_info['type'].to_s != "STORAGE_ISCSI_SAN"
              vlan_tagged.push(network_info['vlanId'])
            else
              vlan_untagged.push(network_info['vlanId'])
            end
          end

        end
        fabric_vlan_info["#{fabric}"]['tagged_vlan'] = vlan_tagged.uniq
        fabric_vlan_info["#{fabric}"]['untagged_vlan'] = vlan_untagged.uniq
        logger.debug("fabric_vlan_info: #{fabric_vlan_info.inspect}")
      end
    end
    fabric_vlan_info
  end

  # Get the count of interfaces
  def get_server_nic_type(server_component, server_cert)
    server_conf = ASM::Util.build_component_configuration(server_component, :decrypt => decrypt?)
    network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
    # get fabric information
    network_fabric_info = {}
    network_info = network_params['network_configuration']
    fabrics = network_info['fabrics']
    fabrics.each do |fabric|
      redundancy =  fabric['redundancy']
      interface_names = []
      interface_count = fabric['interfaces'].count
      fabric['interfaces'].each do |interface|
        interface_names << interface['name']
      end
      fabric_id = fabric['name'].match(/Fabric\s+(\S+)/)[1]
      fabric_interface_names= interface_names.collect{|x| x.match(/Interface #{fabric_id}/)}
      network_fabric_info["#{fabric['name']}"] = ( interface_count * 2) / fabric_interface_names.count
    end
    logger.debug"network_info: #{network_fabric_info}"
    return network_fabric_info
  end
  
  def get_iscsi_fabric(server_component,server_cert)
    server_conf = ASM::Util.build_component_configuration(server_component, :decrypt => decrypt?)
    network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
    # get fabric information
    if network_params
      network_fabric_info = {}
      network_info = network_params['network_configuration']
      fabrics = network_info['fabrics']
      if fabrics
        fabrics.each do |fabric|
          fabric_networks = []
          fabic_interfaces = fabric['interfaces']
          if fabic_interfaces
            networks = []
            fabic_interfaces.each do |fabic_interface|
              partitions = fabic_interface['partitions']
              networks = partitions.collect { |partition| partition['networkObjects'] }.flatten
              fabric_networks.concat(networks)
            end
          end
          network_fabric_info["#{fabric['name']}"] = fabric_networks
        end
      end
      logger.debug"network_info: #{network_fabric_info}"

      fabric_iscsi_info = get_iscsi_fabric_vlan_info(network_fabric_info)
      logger.debug("Found Fabric VLAN INFO: #{fabric_iscsi_info}")
    else
      fabric_iscsi_info = ['Fabric A']
      logger.debug("Defaulted to Fabric VLAN INFO: #{fabric_iscsi_info}")
    end

    unless fabric_iscsi_info.uniq.size == 1
      raise(Exception, "Expected to find only one iscsi fabric, found #{fabric_iscsi_info.uniq.size}")
    end
      
    fabric_iscsi_info.compact.uniq
  end
  
  def get_iscsi_fabric_vlan_info(network_fabric_info)
    logger.debug "Inside get_iscsi_fabric_vlan_info"
    iscsi_fabric = []
    fabric_vlan_info = {}
    ["Fabric A", "Fabric B", "Fabric C"].each do |fabric|
      logger.debug "Process fabric: #{fabric}"
      fabric_vlan_info["#{fabric}"] = {}
      if network_fabric_info["#{fabric}"]
        network_fabric_info["#{fabric}"].each do |network_info|
          logger.debug "network info: #{network_info}"
          if network_info
            if network_info['type'].to_s == "STORAGE_ISCSI_SAN"
              iscsi_fabric.push(fabric)
            end
          end
        end
      end
    end
    iscsi_fabric.uniq.compact
  end

  def reset_servers(migration_components)
    migration_components['SERVER'].each do |migration_component|
      server_cert = migration_component['puppetCertName']
      logger.info("Processing server component: #{migration_component['puppetCertName']}")
      server_conf = ASM::Util.build_component_configuration(migration_component, :decrypt => decrypt?)
      oldserver_info = (server_conf['asm::baseserver'] || {})
      if !oldserver_info
        raise(Exception,"Old server information is not provided for migration")
      end
      old_server_cert = oldserver_info.keys[0]
      logger.debug("Old server certificate name: #{old_server_cert}")
      begin
        cleanup_server(migration_component,old_server_cert)
        endpoint = ASM::Util.parse_device_config(old_server_cert)
        ASM::WsMan.poweroff(endpoint,logger)
        
        # power on the new server to support the iDRAC module
        endpoint = ASM::Util.parse_device_config(server_cert)
        ASM::WsMan.poweroff(endpoint,logger)
        
        # Cleanup compellent server object
        cleanup_compellent(migration_component,old_server_cert)
      rescue Exception => e
        logger.debug("Exception occured during the server cleanup/poweroff. Message: #{e.message}")
        logger.debug("Stack Trace: #{e.inspect}\n\n#{e.backtrace}")
      end
    end
  end

  #Resets VirtualMac Addresses to permanent mac addresses
  def cleanup_server(server_component, old_server_cert)
    server_conf = ASM::Util.build_component_configuration(server_component, :decrypt => decrypt?)
    server_cert = server_component['puppetCertName']
    network_params = (server_conf['asm::esxiscsiconfig'] || {})[server_cert]
    net_config = nil
    device_conf = {}
    # get fabric information
    if network_params
      net_config = ASM::NetworkConfiguration.new(network_params['network_configuration'])
      device_conf = ASM::Util.parse_device_config(old_server_cert)
      options = { :add_partitions => true }
      net_config.add_nics!(device_conf, options)
      logger.debug("Resetting virtual mac addresses to permanent mac addresses for: #{old_server_cert}")
      net_config.reset_virt_mac_addr(device_conf)

      network_params['network_configuration'] = net_config.to_hash
      server_conf.delete('asm::server')
      server_conf.delete('asm::baseserver')
      server_conf.delete('asm::esxiscsiconfig')
      # Rename the cert name in the resource hash from new cert to old certname
      new_conf = {}
      new_conf['asm::idrac'] = Hash[server_conf['asm::idrac'].map {|k,v| [old_server_cert,v]}]
      #new_conf['asm::esxiscsiconfig'] = Hash[server_conf['asm::esxiscsiconfig'].map {|k,v| [old_server_cert,v]}]

      inventory = ASM::Util.fetch_server_inventory(old_server_cert)
      new_conf['asm::idrac'][old_server_cert]['nfsipaddress'] = ASM::Util.get_preferred_ip(device_conf[:host])
      new_conf['asm::idrac'][old_server_cert]['nfssharepath'] = '/var/nfs/idrac_config_xml'
      new_conf['asm::idrac'][old_server_cert]['servicetag'] = inventory['serviceTag']
      new_conf['asm::idrac'][old_server_cert]['model'] = inventory['model'].split(' ').last.downcase
      new_conf['asm::idrac'][old_server_cert]['network_configuration'] =  net_config.to_hash

      process_generic(old_server_cert, new_conf, 'apply', 'true')
    end
  end

  def get_vlan_info(partition_network_objects,target_boot_device,os_image_type)
    vlan_info = {}
    vlan_info['tagged'] = []
    vlan_info['untagged'] = []
    if partition_network_objects.nil?
      return vlan_info
    end
    partition_network_objects.each do |partition_network_object|
      vlanId = partition_network_object['vlanId']
      network_type = partition_network_object['type']
      if target_boot_device == "iSCSI" and network_type == "STORAGE_ISCSI_SAN"
        logger.debug("Inside iscsi device loop")
        vlan_info['untagged'].push(vlanId)
      elsif !@supported_os_postinstall.include?(os_image_type.downcase)
        logger.debug("Inside other OS loop: #{os_image_type.downcase}")
        vlan_info['untagged'].push(vlanId)
      elsif network_type == "PXE"
        logger.debug("Inside the PXE vlan loop")
        vlan_info['untagged'].push(vlanId)
      else
        logger.debug("Inside the default loop")
        vlan_info['tagged'].push(vlanId)
      end
      logger.debug("VLAN INFO so far: #{vlan_info}")
    end
    vlan_info
  end

  
  def cleanup_compellent(component,old_cert_name)
    server_cert_name = component['puppetCertName']
    logger.debug("Cert name: #{server_cert_name}")
    related_storage_components = find_related_components('STORAGE', component)
    server_fc_cleanup_hash = {}
    service_tag=ASM::Util.cert2serial(old_cert_name)
    boot_server_object="ASM_#{service_tag}"
          
    related_storage_components.each do |related_storage_component|
      compellent_cert_name = related_storage_component['puppetCertName']
      resource_hash = ASM::Util.build_component_configuration(related_storage_component, :decrypt => decrypt?)
      if resource_hash['compellent::createvol']
        volume_name = resource_hash['compellent::createvol'].keys[0]
        params = resource_hash['compellent::createvol'][volume_name]
        server_fc_cleanup_hash['compellent::volume_map'] ||= {}
        server_fc_cleanup_hash['compellent::volume_map'][volume_name] ||= {}
        server_fc_cleanup_hash['compellent::volume_map'][volume_name] = {
          'ensure' => 'absent',
          'volumefolder' => params['volumefolder'],
          'force' => 'true',
          'servername' => boot_server_object,
        }
      end
      logger.debug("ASM FC Cleanup resource hash: #{server_fc_cleanup_hash}")
      if server_fc_cleanup_hash
        process_generic(
        compellent_cert_name,
        server_fc_cleanup_hash,
        'device',
        true,
        nil,
        component['asmGUID']
        )
      end
    end
  end

  def reconfigure_ha_for_clusters(certname, clusters)
    conf = ASM::Util.parse_device_config(certname)
    require 'rbvmomi'

    options = {
      :host => conf.host,
      :user => conf.user,
      :password => conf.password,
      :insecure => true,
    }
    vim = RbVmomi::VIM.connect(options)
    clusters.each do |path|
      dc = vim.serviceInstance.find_datacenter(path.split('/').first)
      dc.hostFolder.childEntity.each do |cluster|
        if cluster.name == path.split('/').last
          cluster.host.each do |host|
            host.ReconfigureHostForDAS_Task
          end 
        end
      end
    end
    # we must wait for these tasks to finish
    sleep (300)
  end

end

class Hash
   def keep_merge(hash)
      target = dup
      hash.keys.each do |key|
         if hash[key].is_a? Hash and self[key].is_a? Hash
            target[key] = target[key].keep_merge(hash[key])
            next
         end
         #target[key] = hash[key]
         target.update(hash) { |key, *values| values.flatten.uniq }
      end
      target
   end
end
