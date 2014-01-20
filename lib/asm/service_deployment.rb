require 'asm'
require 'asm/util'
require 'fileutils'
require 'json'
require 'logger'
require 'open3'
require 'rest_client'
require 'yaml'

class ASM::ServiceDeployment

  class CommandException < Exception; end

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
        file.write(JSON.pretty_generate(service_deployment))
      end

      # TODO: pass deployment into constructor instead of here
      @deployment = service_deployment

      # Will need to access other component types during deployment
      # of a given component type in the future, e.g. VSwitch configuration
      # information is contained in the server component type data
      @components_by_type = components_by_type(service_deployment)
      process_components()
    rescue Exception => e
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
      ASM::Util.run_command(cmd, puppet_out)
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
      title = match[2].upcase
    end
    title
  end

  def process_server(component)
    log("Processing server component: #{component['id']}")
    cert_name = component['id']

    resource_hash = {}
    deviceconf = nil
    inventory = nil
    resources = ASM::Util.asm_json_array(component['resources'])
    resources.each do |resource|
      if resource['id'] =~ /asm::server/i
        resource_hash = ASM::Util.append_resource_configuration!(resource, resource_hash)
      elsif resource['id'] =~ /asm::idrac/i
        deviceconf ||= ASM::Util.parse_device_config(cert_name)
        inventory  ||= ASM::Util.fetch_server_inventory(cert_name)
        resource_hash = ASM::Util.append_resource_configuration!(resource, resource_hash)
      end
    end

    server_params = {}
    (resource_hash['asm::server'] || {}).each do |title, params|
      if params['rule_number']
        raise(Exception, "Did not expect rule_number in asm::server")
      else
        params['rule_number'] = rule_number
      end

      # In the case of Dell servers the title should contain 
      # the service tag and we retrieve it here
      title = cert_name_to_service_tag(title)
      
      # TODO: if present this should go in kickstart
      params.delete('custom_script')

      server_params[title] = params
    end

    if server_params.size > 0
      resource_hash['asm::server'] = server_params
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
        service_tag = cert_name_to_service_tag(title)
        params['before'] = "Asm::Server[#{service_tag}]"
      end
      
    end
    process_generic(component['id'], resource_hash, 'apply', 'true')
    unless @debug
      (resource_hash['asm::server'] || []).each do |title, params|
        block_until_server_ready(title, params, timeout=3600)
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
    end

    
    # Add ESXi hosts and creds as separte resources
    (@components_by_type['SERVER'] || []).each do |server_component|
      server_conf = ASM::Util.build_component_configuration(server_component)
      (server_conf['asm::server'] || []).each do |title, params|
        if params['os_image_type'] == 'vmware_esxi'
          server_cert = title
          serverdeviceconf = ASM::Util.parse_device_config(server_cert)
          resource_hash['asm::host'] ||= {}
          resource_hash['asm::host'][server_cert] = {
            'esx_host' => serverdeviceconf[:host],
            'esx_user' => serverdeviceconf[:user],
            'esx_password' => serverdeviceconf[:password],
          }
        end
      end
    end
    
    process_generic(cert_name, resource_hash, 'apply')
  end

  def process_virtualmachine(component)
    log("Processing virtualmachine component: #{component['id']}")
    config = ASM::Util.build_component_configuration(component)
    process_generic(component['id'], config, 'apply')
  end

  def process_service(component)
    log("Processing service component: #{component['id']}")
    config = ASM::Util.build_component_configuration(component)
    process_generic(component['id'], config, 'apply')
  end


  # converts from an ASM style server resource into
  # a method call to check if the esx host is up
  def block_until_server_ready(serial_num, params, timeout=3600)
    password = params['admin_password'] || raise(Exception, "resource #{serial_num} is missing required server attribute admin_password")
    type = params['os_image_type'] || raise(Exception, "resource #{serial_num} is missing required server attribute os_image_type")
    hostname = params['os_host_name'] || raise(Exception, "resource #{serial_num} is missing required server attribute os_host_name")

    if type == 'vmware_esxi'
      ip_address = nil
      log("Waiting until #{hostname} has checked in with Razor")
      ASM::Util.block_and_retry_until_ready(timeout, CommandException, 30) do
        results = get('nodes').each do |node|
          results = get('nodes', node['name'])
          serial  = results['facts']['serialnumber']
          if serial == serial_num
            ip_address = results['facts']['ipaddress']
            log("Found ip address!! #{ip_address}")
          else
            log("Did not find a razor node matching serial number: #{serial_num}")
          end
        end
        unless ip_address
          raise(CommandException, "Did not find our node by its serial number. Will try again")
        end
        log("#{hostname} has checked in with Razor with ip address #{ip_address}")
      end
      log("Waiting until #{hostname} is ready")
      ASM::Util.block_and_retry_until_ready(timeout, CommandException, 150) do
        esx_command =  "system uuid get"
        cmd = "esxcli --server=#{ip_address} --username=root --password=#{password} #{esx_command}"
        log("Running command: #{cmd}")
        results = ASM::Util.run_command_simple(cmd)
        logger.debug(results.inspect)
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
