require 'logger'
require 'fileutils'
require 'open3'
require 'io/wait'
require 'timeout'

class ASM

  require 'asm/service_deployment'

  # TODO these methods shoudl be initialized from sinatra b/c their first invocation
  # is not thread safe

  # provides a single call that can be used to initialize our mutex
  def self.init
    if @deployment_mutex
      raise("Can not initialize ASM class twice")
    else
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

  def self.run_command_simple(cmd)
    logger.info("Executing command: #{cmd}")
    result = {}
    Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
      result['pid']         = wait_thr[:pid]
      result['exit_status'] = wait_thr.value
      result['stdout']      = stdout.read
      result['stderr']      = stderr.read
    end
    result
  end

  def self.run_command(cmd, outfile)
    logger.info("Executing command: #{cmd}")
    if File.exists?(outfile)
      raise(Exception, "Cowardly refusing to overwrite #{outfile}")
    end
    File.open(outfile, 'w') do |fh|
      Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
        stdin.close

        # Drain stdout
        while line = stdout.gets
          fh.puts(line)
          # Interleave stderr if available
          while stderr.ready?
            if err = stderr.gets
              fh.puts(err)
            end
          end
        end

        # Drain stderr
        while line = stderr.gets
          fh.puts(line)
        end

        fh.close
        raise(Exception, "#{cmd} failed; output in #{outfile}") unless wait_thr.value.exitstatus == 0
      end
    end
  end

  # thread safe counter
  def self.counter
    @deployment_mutex.synchronize do
      @counter ||= 0
      @counter = @counter +1
    end
  end

  def self.block_and_retry_until_ready(timeout, exceptions=nil, &block)
    failures = 0
    status = Timeout::timeout(timeout) do
      begin
        yield
      rescue Exception => e

        exceptions = Array(exceptions)

        if ! exceptions.empty? and (
           exceptions.include?(key = e.class) or
           exceptions.include?(key = key.name.to_s) or
           exceptions.include?(key = key.to_sym))
        then
          logger.info("Caught exception #{e.class}: #{e}")
          failures += 1
          sleep (((2 ** failures) -1) * 0.1)
          retry
        else
          # If the exceptions is not in the list of retry_exceptions re-raise.
          raise e
        end
      end

    end
  end

end
