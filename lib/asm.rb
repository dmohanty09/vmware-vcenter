require 'logger'
require 'fileutils'
require 'asm/service_deployment'
require 'asm/deployment_teardown'

module ASM

  # TODO these methods shoudl be initialized from sinatra b/c their first invocation
  # is not thread safe

  def self.initialized?
    if @deployment_mutex and @certname_mutex and @hostlist_mutex
      true
    else
      nil
    end
  end

  # provides a single call that can be used to initialize our mutex
  def self.init
    if ASM.initialized?
      raise("Can not initialize ASM class twice")
    else
      @certname_mutex   = Mutex.new
      @deployment_mutex = Mutex.new
      @hostlist_mutex   = Mutex.new
      @running_cert_list = []
    end
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
    unless track_service_deployments(id)
      raise(Exception, "Already processing id #{id}. Cannot handle simultaneous requests " +
            "of the same service deployment at the same"
            )
    end
    begin
      service_deployment = ASM::ServiceDeployment.new(id)
      if data['debug'] && data['debug'].downcase == 'true'
        service_deployment.debug = true
      end
      if (data['noop'] || '').downcase == 'true'
        service_deployment.noop = true
      end
      service_deployment.process(data)
    ensure
      complete_deployment(id)
    end
    service_deployment.log("Deployment has completed")
  end

  def self.process_deployment_request(request)
    payload = request.body.read
    data = JSON.parse(payload)
    deployment = data['Deployment']
    ASM.process_deployment(deployment)
  end

  def self.track_service_deployments(id)
    @deployment_mutex.synchronize do
      @running_deployments ||= {}
      track_service_deployments_locked(id)
    end
  end

  def self.complete_deployment(id)
    @deployment_mutex.synchronize do
      @running_deployments.delete(id)
    end
  end

  def self.active_deployments
    @deployment_mutex.synchronize do
      @running_deployments ||= {}
      @running_deployments.keys
    end
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

  def self.block_hostlist(hostlist)
    @hostlist_mutex.synchronize do
      dup_certs = @running_cert_list & hostlist
      if dup_certs.empty?
        @running_cert_list |= hostlist
      end
      return dup_certs
    end
  end

  def self.unblock_hostlist(hostlist)
    @hostlist_mutex.synchronize do
      @running_cert_list -= hostlist
    end
  end

  # thread safe counter
  def self.counter
    @deployment_mutex.synchronize do
      @counter ||= 0
      @counter = @counter +1
    end
  end

  def self.clean_deployment(id)
    ASM::DeploymentTeardown.clean_deployment(id, logger)
  end

  private
  
  def self.clear_mutex
    @certname_mutex = nil
    @deployment_mutex = nil
    @hostlist_mutex   = nil
    @running_cert_list = nil
  end

  def self.track_service_deployments_locked(id)
    if @running_deployments[id]
      return false
    end
    @running_deployments[id] = true
  end

end
