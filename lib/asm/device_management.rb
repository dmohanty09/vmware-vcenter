require 'asm/util'
require 'asm/deployment_teardown'

module ASM
  module DeviceManagement

    #under assumption hash will have at least {"ref_id":"....", "device_type":"...", "service_tag":"...."}, modeled from database entry
    def self.remove_device(cert_name)
        certs = ASM::DeploymentTeardown.get_deployed_certs()

        if certs.include?(cert_name)
          ASM::DeploymentTeardown.clean_deployment_certs([cert_name])
          remove_device_conf(cert_name)
          remove_device_ssl_dir(cert_name)
        end
    end

    def self.remove_device_conf(cert_name)
      conf_file = ASM::Util::DEVICE_CONF_DIR + "/#{cert_name}.conf"
      FileUtils.rm(conf_file)
    end

    def self.remove_device_ssl_dir(device_name)
      ssl_dir = ASM::Util::DEVICE_SSL_DIR + "/#{device_name}"
      FileUtils.rm_rf(ssl_dir, :secure=>true)
    end
  end
end
