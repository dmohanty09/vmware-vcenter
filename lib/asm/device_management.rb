require 'asm'
require 'asm/util'
require 'asm/deployment_teardown'

module ASM
  module DeviceManagement

    #under assumption hash will have at least {"ref_id":"....", "device_type":"...", "service_tag":"...."}, modeled from database entry
    def self.remove_device(cert_name)
        certs = ASM::DeploymentTeardown.get_deployed_certs()

        if certs.include?(cert_name)
          ASM::DeploymentTeardown.clean_deployment_certs([cert_name])
          logger.info("Cleaned certificate for device #{cert_name}...")
          remove_device_conf(cert_name)
          remove_device_ssl_dir(cert_name)
        else
          logger.warn("Couldn't find certificate by the name of #{cert_name}.  No files being cleaned.")
        end
    end

    def self.remove_device_conf(cert_name)
      conf_file = ASM::Util::DEVICE_CONF_DIR + "/#{cert_name}.conf"
      FileUtils.rm(conf_file)
      logger.info("Removed device config file for #{cert_name}")
    end

    def self.remove_device_ssl_dir(device_name)
      #Calling this script is a work around, since the folder to delete is a root:root owned folder, and the call will be made by the razor user
      ASM::Util.run_command_simple("sudo /opt/Dell/scripts/rm-device-ssl.sh #{device_name}")
      logger.info("Cleaned Puppet devices ssl files for #{device_name}")
    end

    def self.logger
      @logger ||= ASM.logger
    end
  end
end
