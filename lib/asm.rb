require 'logger'
require 'puppet'
require 'fileutils'
class ASM

  # TODO these methods shoudl be initialized from sinatra b/c their first invocation
  # is not thread safe

  def self.logger
    @logger ||= Logger.new(File.join("#{base_dir}", 'asm_puppet.log'))
  end

  def self.base_dir
    @base_dir ||= begin
      Puppet.initialize_settings
      work_dir = File.join(Puppet[:confdir], 'asm_working')
      unless File.exists?(work_dir)
        FileUtils.mkdir(work_dir)
      end
      work_dir
    end
  end


  def self.service_deployment_base_dir
    @service_deployment_basedir ||= begin
      work_dir = File.join(ASM.base_dir, 'service_deployments')
      unless File.exists?(work_dir)
        logger.info("Creating new asm service deployment working directory #{work_dir}")
        FileUtils.mkdir(work_dir)
      end
      work_dir
    end
  end

  # serves as a single place to create all deployments
  # ensures that only a single deployment is not done
  # at the same time
  def self.process_deployment(data)
    id = data['id']
    service_deployment = nil
    @deployment_mutex ||= Mutex.new
    @deployment_mutex.synchronize do
      unless track_service_deployments(id)
        raise(Exception, "Already processing id #{id}. Cannot handle simultaneous requests " +
                         "of the same service deployment at the same"
        )
      end
    end
    begin
      service_deployment = ASM::ServiceDeployment.new(id)
      service_deployment.process(data)
    ensure
      complete_deployment(id)
    end
  end

  def self.track_service_deployments(id)
    @running_deployments ||= {}
    if @running_deployments[id]
      return false
    end
    @running_deployments[id] = true
  end

  def self.complete_deployment(id)
    @running_deployments.delete(id)
  end

end
