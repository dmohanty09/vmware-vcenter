require 'asm'
require 'asm/util'
require 'fileutils'
require 'json'
require 'logger'
require 'open3'
require 'rest_client'
require 'timeout'
require 'yaml'

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
    File.open(resource_file, 'w') do |fh|
      fh.write(config.to_yaml)
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
      raise(Exception, "Did not find result line in file #{puppet_out}") unless found_result_line
      results
    end
  end

  # Currently having problems with some resource data for host / vswith
  # when running through "puppet asm". This method provides a 
  # short-term workaround which is to generate a puppet manifest
  # and directly apply that
  def process_generic_direct_apply(cert_name, config)
    raise(Exception, 'Component has no certname') unless cert_name
    log("Starting processing resources for endpoint #{cert_name}")
    resource_file = File.join(resources_dir, "#{cert_name}.pp")
    File.open(resource_file, 'w') do |fh|
      ASM::Util.write_manifest(config, fh)
    end
    cmd = "sudo puppet apply --debug --trace #{resource_file}"
    if @debug
      logger.info("[DEBUG MODE] execution skipped for '#{cmd}'")
    else
      puppet_out = File.join(deployment_dir, "#{cert_name}.out")
      ASM::Util.run_command(cmd, puppet_out)
      # If we got here the command did not fail, so we call it success
      results = {'num_resources' => '1', 'num_failures' => '0', 'other_failures' => '0', 'num_updates' => '1'}
    end
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

    (resource_hash['asm::server'] || {}).each do |title, params|
      if params['rule_number']
        raise(Exception, "Did not expect rule_number in asm::server")
      else
        params['rule_number'] = rule_number
      end

      params['serial_number'] = serial_number

      # Razor policies currently can't be deleted, only disabled. So we
      # need to make sure we use a unique policy name so that we can 
      # disable old policies and assign new ones
      params['policy_name'] = "policy-#{params['serial_number']}-#{@id}"
      
      # TODO: if present this should go in kickstart
      params.delete('custom_script')
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
    # TODO: implement this! Should look through relatedComponents field
    @components_by_type[type]
  end

  def build_portgroup(vswitch, path, hostip, portgroup_name, network, 
                      portgrouptype, active_nics)
    {
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
      'ipsettings' => 'dhcp', # TODO: pull from network pool
      'ipaddress' => '',      # ditto
      'subnetmask' => '',     # ditto
      'traffic_shaping_policy' => 'disabled',
      'averagebandwidth' => 1000,
      'peakbandwidth' => 1000,
      'burstsize' => 1024,
      'vswitch' => vswitch,
      'path' => path,
      'host' => hostip,
      'vlanid' => network['vlanId'],
      'transport' => 'Transport[vcenter]',
      'require' => "Esx_vswitch[#{hostip}:#{vswitch}]",
    }
  end

  def build_vswitch(server_cert, index, network_guid, hostip, 
                  params, server_params)
    vswitch_name = "vSwitch#{index}"
    vmnic1 = "vmnic#{index * 2}"
    vmnic2 = "vmnic#{(index * 2) + 1}"
    path = "/#{params['datacenter']}/#{params['cluster']}"

    network = ASM::Util.fetch_network_settings(network_guid)

    nics = [ vmnic1, vmnic2 ]
    ret = { 'esx_vswitch' => {}, 'esx_portgroup' => {}, }
    ret['esx_vswitch']["#{hostip}:#{vswitch_name}"] = {
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
    if index == 3
      # iSCSI network
      ['ISCSI0', 'ISCSI1'].each_with_index do |portgroup_name, index|
        portgroup = build_portgroup(vswitch_name, path, hostip, portgroup_name,
                                    network, portgrouptype, [ nics[index] ])
        ret['esx_portgroup'][portgroup_name] = portgroup
      end
    else
      if index == 2
        # Workload group has portgrouptype = 'VirtualMachine'
        portgrouptype = 'VirtualMachine'
      end
      portgroup = build_portgroup(vswitch_name, path, hostip, network['name'], 
                                  network, portgrouptype, nics)
      ret['esx_portgroup'][network['name']] = portgroup
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
              storage_network_guid = nil
              [ 'hypervisor_network', 'vmotion_network', 'workload_network', 'storage_network' ].each_with_index do | type, index |
                guid = network_params[type]
                if type == 'workload_network'
                  log("TODO: add workload network(s) #{guid}")
                else
                  if guid and !guid.empty? and guid.to_s != '-1'
                    log("Configuring #{type} = #{guid}")

                    if type == 'storage_network'
                      storage_network_guid = guid
                    end

                    vswitch_resources = build_vswitch(server_cert, index,
                                                      guid, hostip,
                                                      params, server_params)
                    # Should be exactly one vswitch in response
                    vswitch_title = vswitch_resources['esx_vswitch'].keys[0]
                    vswitch = vswitch_resources['esx_vswitch'][vswitch_title]
                    vswitch['require'] = next_require

                    # Set next require to this vswitch so they are all
                    # ordered properly
                    next_require = "Esx_vswitch[#{vswitch_title}]"
                    
                    log("Built vswitch resources = #{vswitch_resources.to_yaml}")

                    # merge these in
                    resource_hash['esx_vswitch'] = (resource_hash['esx_vswitch'] || {}).merge(vswitch_resources['esx_vswitch'])
                    resource_hash['esx_portgroup'] = (resource_hash['esx_portgroup'] || {}).merge(vswitch_resources['esx_portgroup'])
                  end
                end
              end
            end
          end
        end
      end
    end
    process_generic_direct_apply(cert_name, resource_hash)
  end

  def process_virtualmachine(component)
    log("Processing virtualmachine component: #{component['id']}")
    resource_hash = ASM::Util.build_component_configuration(component)
    
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

    # TODO: title is not set correctly, needs to come from asm::server
    # section
    hostname = nil
    resource_hash['asm::vm'].each do |title, params|
      ['cluster', 'datacenter', 'datastore'].each do |key|
        params[key] = cluster_params[key]
      end

      if resource_hash['asm::server']
        server_params = (resource_hash['asm::server'][title] || {})
      else
        server_params = {}
      end
                         
      if server_params['os_type'] == 'windows'
        params['os_type'] = 'windows'
      else
        params['os_type'] = 'linux'
      end
      params['hostname'] = server_params['os_host_name']
      hostname ||= params['hostname']
      params['vcenter_username'] = cluster_deviceconf[:user]
      params['vcenter_password'] = cluster_deviceconf[:password]
      params['vcenter_server'] = cluster_deviceconf[:host]
      params['vcenter_options'] = { 'insecure' => true }
      params['ensure'] = 'present'
    end

    asm_server_params = resource_hash.delete('asm::server')
    log("Creating VM #{hostname}")
    process_generic(component['id'], resource_hash, 'apply')

    # TODO: Puppet module does not power it on first time.
    log("Powering on #{hostname}")
    process_generic(component['id'], resource_hash, 'apply')

    if asm_server_params
      uuid = ASM::Util.find_vm_uuid(hostname)
      log("Found UUID #{uuid} for #{hostname}")
      server_resource_hash = { 'asm::server' => asm_server_params }
      log("Initiating O/S install for VM #{hostname}")
      process_generic(component['id'], server_resource_hash, 'apply')
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

end
