require 'logger'
require 'fileutils'
require 'asm/service_deployment'
require 'asm/service_migration_deployment'
require 'asm/deployment_teardown'
require 'asm/update_deployment'
require 'asm/config'
require 'asm/errors'
require 'asm/data/deployment'
require 'sequel'

module ASM

  # TODO these methods shoudl be initialized from sinatra b/c their first invocation
  # is not thread safe

  class UninitializedException < StandardError; end

  def self.initialized?
    if @initialized
      true
    else
      nil
    end
  end

  # provides a single call that can be used to initialize our mutex
  def self.init(config_file = nil)
    if ASM.initialized?
      raise("Can not initialize ASM class twice")
    else
      @certname_mutex   = Mutex.new
      @deployment_mutex = Mutex.new
      @hostlist_mutex   = Mutex.new
      @running_cert_list = []
      @config = ASM::Config.new(config_file)
      @database = Sequel.connect(@config.database_url, :loggers => [logger])
      @initialized = true
    end
  end

  def self.config
    @config
  end

  def self.base_dir
    @base_dir ||= begin
      dir = config.base_dir
      FileUtils.mkdir_p(dir)
      dir
    end
  end

  def self.logger
    @logger ||= begin
      # NOTE: using eval to build the logger. Anyone with write access to our
      # config file can do code injection. Do not do this with user-provided input!
      eval(config.logger)
    end
  end

  def self.database
    @database or raise(UninitializedException)
  end

  # Serves as a single place to execute deployments and ensure that the same
  # deployment is not executed more than once concurrently.
  #
  # setup_block will be executed within the exclusion so that it is not
  # executed concurrently either.
  def self.process_deployment(data, deployment_db, &setup_block)
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
      yield setup_block

      service_deployment = ASM::ServiceDeployment.new(id, deployment_db)
      service_deployment.debug = ASM::Util.to_boolean(data['debug'])
      service_deployment.noop = ASM::Util.to_boolean(data['noop'])
      service_deployment.is_retry = ASM::Util.to_boolean(data['retry'])
      service_deployment.process(data)
    ensure
      complete_deployment(id)
    end
    service_deployment.log("Deployment has completed")
  end

  def self.process_deployment_migration(request)
    payload = request.body.read
    deployment = JSON.parse(payload)

    data = ASM::Data::Deployment.new(database)
    ASM.process_deployment(deployment, data) do
      ASM::ServiceMigrationDeployment.prep_deployment_dir(deployment)

      ASM.logger.info('Initiating the server migration')
      deployment['migration'] = 'true'
      deployment['retry'] = 'true'
      data.load(deployment['id'])
    end
  end

  def self.process_deployment_request(request)
    payload = request.body.read
    deployment = JSON.parse(payload)
    data = ASM::Data::Deployment.new(database)
    ASM.process_deployment(deployment, data) do
      data.create(deployment['id'], deployment['deploymentName'])
    end
  end

  # TODO: 404 on not found

  def self.clean_deployment(id)
    Thread.new do
      ASM::DeploymentTeardown.clean_deployment(id, logger)
      deployment = ASM::DeploymentTeardown.deployment_data(id)
      data = ASM::Data::Deployment.new(database)
      data.load(deployment['id'])
      data.delete
    end
  end

  def self.retry_deployment(id, deployment)
    data = ASM::Data::Deployment.new(database)
    ASM.process_deployment(deployment, data) do
      ASM::UpdateDeployment.backup_deployment_dirs(id,deployment)

      ASM.logger.info("Re-running deployment; this will take awhile ...")
      data.load(deployment['id'])
    end
  end

  def self.get_deployment_status(asm_guid)
    deployment_data = ASM::Data::Deployment.new(database)
    deployment_data.load(asm_guid)
    deployment_data.get_execution(0)
  end

  def self.process_deployment_request_migration(request)
    payload = request.body.read
    data = JSON.parse(payload)
    deployment = data
    ASM.process_deployment_migration(deployment)
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
    raise(UninitializedException) unless self.initialized?
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

  private

  def self.reset
    @certname_mutex   = nil
    @deployment_mutex = nil
    @hostlist_mutex   = nil
    @running_cert_list = nil
    @logger = nil
    @config = nil
    @database.disconnect if @database
    @database = nil
    @base_dir = nil
    @initialized = false
  end

  def self.track_service_deployments_locked(id)
    if @running_deployments[id]
      return false
    end
    @running_deployments[id] = true
  end

end
