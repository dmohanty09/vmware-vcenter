require 'asm'
require 'asm/util'
require 'yaml'
require 'logger'
require 'fileutils'
require 'open3'
require 'rest_client'

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

  def process(service_deployment)
    ASM.logger.info("Deploying #{service_deployment['deploymentName']} with id #{service_deployment['id']}")
    log("Starting deployment #{service_deployment['deploymentName']}")
    component_hash = component_hash(service_deployment)
    process_components(component_hash)
  end

  def component_hash(service_deployment)
    component_hash = {}
    if service_deployment['serviceTemplate']
      unless service_deployment['serviceTemplate']['components']
        logger.warn("service deployment data has no components")
      end
    else
      logger.warn("Service deployment data has no serviceTemplate defined")
    end
    components = ((service_deployment['serviceTemplate'] || {})['components'] || [])

    # API is sending hash for single element and array for list
    if components.is_a?(Hash)
      logger.debug("Received single hash for components")
      components = [ components ]
    end

    logger.debug("Found #{components.length} components")
    components.each do |component|
      logger.debug("Found component id #{component['id']}")
      component_hash[component['type']] ||= []
      component_hash[component['type']].push(component)
    end
    component_hash
  end

  def process_components(component_hash)
    ['STORAGE', 'TOR', 'SERVER', 'CLUSTER', 'VIRTUALMACHINE', 'SERVICE', 'TEST'].each do |type|
      if components = component_hash[type]
        log("Processing components of type #{type}")
        components.collect do |comp|
          #
          # TODO: this is some pretty primitive thread management, we need to use
          # something smarter that actually uses a thread pool
          #
          Thread.new do
            send("process_#{type.downcase}", comp)
          end
        end.each do |thrd|
          thrd.join
        end
        log("Finsished components of type #{type}")
      end
    end
  end

  def asm_to_puppet_params(resource, resource_type=nil, puppet_cert_name=nil)
    param_hash = {}
    resource['parameters'].each do |param|
      if param['value']
        param_hash[param['id']] = param['value']
      else
        if resource_type and puppet_cert_name
          logger.warn("Parameter #{param['id']} of type #{resource_type} for #{puppet_cert_name} has no value, skipping")
        end
      end
    end
    param_hash
  end

  def process_generic(component, puppet_run_type = 'device', override = nil)
    puppet_cert_name = component['id'] || raise(Exception, 'Component has no certname')
    log("Starting processing resources for endpoint #{puppet_cert_name}")
    resource_hash = {}
    resources = (component['resources'] || [])
    # API is sending hash for single element and array for list
    if resources.is_a?(Hash)
      logger.debug("Received single hash for resources")
      resources = [ resources ]
    end
    resources.each do |resource|
      resource_type = resource['id'] || raise(Exception, 'resource found with no type')
      resource_hash[resource_type] ||= {}
      raise(Exception, "resource of type #{resource_type} has no parameters") unless resource['parameters']
      param_hash = asm_to_puppet_params(resource, resource_type, puppet_cert_name)

      unless title = param_hash.delete('title')
        raise(Exception, "Resource from component type #{component['type']}" +
              " has resource #{resource['id']} with no title")

      end
      resource_hash[resource_type][title] = param_hash
      resource_file = File.join(resources_dir, "#{puppet_cert_name}.yaml")
      File.open(resource_file, 'w') do |fh|
        fh.write(resource_hash.to_yaml)
      end
      override_opt = override ? "--always-override " : ""
      cmd = "sudo puppet asm process_node --filename #{resource_file} --run_type #{puppet_run_type} #{override_opt}#{puppet_cert_name}"
      puppet_out = File.join(deployment_dir, "#{puppet_cert_name}.out")
      log("Running command: #{cmd}")
      ASM::Util.run_command(cmd, puppet_out)
      last_line = File.readlines(puppet_out).last
      if last_line =~ /Results: For (\d+) resources. (\d+) failed. (\d+) updated successfully./
        log("Results for endpoint #{puppet_cert_name} configuration")
        log("  #{last_line.chomp}")
        return {'total' => $1, 'failed' => $2 ,'updated' => $3}
      else
        raise(Exception, "Puppet output did not have expected result line, see #{puppet_out} for more info")
      end
    end
  end

  def process_test(component)
    process_generic(component, 'apply', true)
  end

  def process_storage(component)
    log("Processing storage component: #{component['id']}")
    process_generic(component)
  end

  def process_tor(component)
    log("Processing tor component: #{component['id']}")
    process_generic(component)
  end

  def process_server(component)
    log("Processing server component: #{component['id']}")
    component['resources'].each_with_index do |r, index|
      if r['id'].downcase == 'asm::server'
        # add a rule_number
        r['parameters'].each do |param|
          if param['id'] == 'rule_number'
            raise(Exception, "Did not expect rule_number in asm::server")
          end
        end
        component['resources'][index]['parameters'].push({
          'id' => 'rule_number',
          'value' => rule_number
        })
        # configure razor
        process_generic(component, 'apply', 'true')
        block_until_server_ready(r, timeout=3600)
      else
        logger.warn("Unexpected resource type for server: #{r['id']}")
      end
    end
  end

  #
  # Razor requires unique rule numbers per deployment that set priotity.
  # This routine is able to safely generate 100 per second.
  #
  def rule_number
    (Integer(Time.now.strftime("%s")) * 100) + (ASM.counter % 100)
  end

  def process_cluster(component)
    log("Processing cluster component: #{component['id']}")
    process_generic(component)
  end

  def process_virtualmachine(component)
    log("Processing virtualmachine component: #{component['id']}")
    process_generic(component)
  end

  def process_service(component)
    log("Processing service component: #{component['id']}")
    process_generic(component)
  end


  # converts from an ASM style server resource into
  # a method call to check if the esx host is up
  def block_until_server_ready(resource, timeout=3600)
    params = asm_to_puppet_params(resource)
    password   = params['admin_password']
    type       = params['os_image_type']
    hostname   = params['os_host_name']
    serial_num = params['title']

    unless password and type and hostname and serial_num
      raise(Exception, "resource #{params['title']} is missing required server attributes")
    end

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
