require 'asm'
require 'yaml'
require 'logger'
require 'fileutils'
require 'open3'

class ASM::ServiceDeployment

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
    ((service_deployment['serviceTemplate'] || {})['components'] || []).each do |component|
      component_hash[component['type']] ||= []
      component_hash[component['type']].push(component)
    end
    component_hash
  end

  def process_components(component_hash)
    dir = resources_dir
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

  def process_generic(component, puppet_run_type = 'device', override = nil)
    puppet_cert_name = component['id'] || raise(Exception, 'Component has no certname')
    log("Starting processing resources for endpoint #{puppet_cert_name}")
    resource_hash = {}
    (component['resources'] || []).each do |resource|
      resource_type = resource['id'] || raise(Exception, 'resource found with no type')
      resource_hash[resource_type] ||= {}
      param_hash = {}
      raise(Exception, "resource of type #{resource_type} has no parameters") unless resource['parameters']
      resource['parameters'].each do |param|
        param_hash[param['id']] = param['value']
      end

      if param_hash.has_key?('title')
        unless title = param_hash.delete('title')
          raise(Exception, "Resource from component type #{component['type']}" +
                " has resource #{resource['id']} with no title value")
        end
      else
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
      ASM.run_command(cmd, puppet_out)
      last_line = File.readlines(puppet_out).last
      if last_line =~ /Results: For (\d+) resources. (\d+) failed. (\d+) updated successfully./
        log("Results for endpoint #{puppet_cert_name} configuration")
        log("  #{last_line.chomp}")
        return {'total' => $1, 'failed' => $2 ,'updated' => $3}
      else
        raise(Exception, 'Puppet output did not have expected result line')
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
    process_generic(component)
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

end
