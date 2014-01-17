require 'logger'
require 'fileutils'
require 'asm/service_deployment'

module ASM

  # TODO these methods shoudl be initialized from sinatra b/c their first invocation
  # is not thread safe

  # provides a single call that can be used to initialize our mutex
  def self.init
    if @deployment_mutex || @certname_mutex
      raise("Can not initialize ASM class twice")
    else
      @certname_mutex   = Mutex.new
      @deployment_mutex = Mutex.new
    end
  end

  def self.clear_mutex
    @deployment_mutex = nil
  end

  def self.logger
    @logger ||= Logger.new(File.join("#{base_dir}", 'asm_puppet.log'))
  end

  def self.base_dir
    @base_dir ||= begin
      dir = '/opt/Dell/ASM/deployments'
      FileUtils.mkdir_p(dir)
      dir
    end
  end

  # serves as a single place to create all deployments
  # ensures that only a single deployment is not done
  # at the same time
  def self.process_deployment(data)
    id = data['id']
    service_deployment = nil
    unless @deployment_mutex
      raise(Exception, "Must call ASM.init to initialize mutex")
    end
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
      @deployment_mutex.synchronize do
        complete_deployment(id)
      end
    end
    service_deployment.log("Deployment has completed")
  end

  def self.process_deployment_request(request)
    payload = request.body.read
    logger.debug("Received deployment request: #{payload}")
    data = JSON.parse(payload)
    ASM.process_deployment(data['Deployment'])
  end

  def self.debug_deployment_request(request)
    payload = request.body.read
    logger.debug("Received deployment request: #{payload}")
    data = JSON.parse(payload)['Deployment']
    deployment = ASM::ServiceDeployment.new(data['id'])
    deployment.debug = true
    deployment.process(data)
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

  def self.block_certname(certname)
    @certname_mutex.synchronize do
      @running_certs ||= {}
      return false if @running_certs[certname]
      @running_certs[certname] = true
    end
  end

  def self.unblock_certname(certname)
    @certname_mutex.synchronize do
      @running_certs.delete(certname)
    end
  end

  # thread safe counter
  def self.counter
    @deployment_mutex.synchronize do
      @counter ||= 0
      @counter = @counter +1
    end
  end

end
