require 'ostruct'
require 'rest_client'
require 'uri'
require 'open3'
require 'io/wait'
require 'timeout'

module ASM
  module Util

    SERVER_RA_URL='http://localhost:9080/ServerRA/Server'
    # TODO: give razor user access to this directory
    DEVICE_CONF_DIR='/etc/puppetlabs/puppet/devices'
    IDRAC_CONF_DIR='/var/nfs/idrac_config_xml'

    # Given a server ref_id, look up its creds from puppet device conf
    # file and its ASM server inventory from ASM ServerRA REST service.
    # Generate corresponding idrac resource
    def self.generate_idrac_resource(ref_id)
      conf_file = File.join(DEVICE_CONF_DIR, "#{ref_id}.conf")
      conf = parse_device_config(conf_file)
      raise(Exception, "Failed to get device config file for Server #{ref_id}") if conf[ref_id].nil?
      uri = URI.parse(conf[ref_id].url)
      host = uri.host
      user = URI.decode(uri.user)
      password = URI.decode(uri.password)
    
      inventory = fetch_server_inventory(ref_id)
      # Model is like 'PowerEdge M620', convert to m620
      model = inventory['model'].split(' ').last.downcase
      servicetag = inventory['serviceTag']

      idrac_xml = 'default.xml'
      if File.exists?(File.join(IDRAC_CONF_DIR, "#{model}.xml"))
        idrac_xml = "#{model}.xml"
      end

      params = {'dracipaddress' => host,
        'dracusername' => user,
        'dracpassword' => password,
        'configxmlfilename' => idrac_xml,
        'nfsipaddress' => 'localhost',
        'nfssharepath' => IDRAC_CONF_DIR,
      }

      {'importsystemconfiguration' => { servicetag => params } }
    end

    # See spec/fixtures/asm_server_m620.json for sample response
    def self.fetch_server_inventory(ref_id)
      url = "#{SERVER_RA_URL}/#{ref_id}"
      data = RestClient.get(url, {:accept => :json})
      ret = JSON.parse(data)
      raise(Exception, "Failed to get inventory for server #{ref_id}") if ret['refId'] != ref_id
      ret
    end

    # Parse puppet device config files, code cribbed from 
    # Puppet::Util::NetworkDevice::Config
    def self.parse_device_config(file)
      begin
        devices = {}
        device = nil
        File.open(file) { |f|
          count = 1
          f.each { |line|
            case line
            when /^\s*#/ # skip comments
              count += 1
              next
            when /^\s*$/  # skip blank lines
              count += 1
              next
            when /^\[([\w.-]+)\]\s*$/ # [device.fqdn]
              name = $1
              name.chomp!
              raise(Exception, "Duplicate device found at line #{count}, already found at #{device.line}") if devices.include?(name)
              device = OpenStruct.new
              device.name = name
              device.line = count
              device.options = { :debug => false }
              devices[name] = device
            when /^\s*(type|url|debug)(\s+(.+))*$/
              parse_device_config_directive(device, $1, $3, count)
            else
              raise(Exception, "Invalid line #{count}: #{line}")
            end
            count += 1
          }
        }
        devices
      end
    end

    def self.parse_device_config_directive(device, var, value, count)
      case var
      when "type"
        device.provider = value
      when "url"
        device.url = value
      when "debug"
        device.options[:debug] = true
      else
        raise(Exception, "Invalid argument '#{var}' at line #{count}")
      end
    end

    def self.run_command_simple(cmd)
      result = {}
      Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
        result['pid']         = wait_thr[:pid]
        result['exit_status'] = wait_thr.value.exitstatus
        result['stdout']      = stdout.read
        result['stderr']      = stderr.read
      end
      result
    end

    def self.run_command(cmd, outfile)
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

    def self.block_and_retry_until_ready(timeout, exceptions=nil, logger=ASM.logger, &block)
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
end
