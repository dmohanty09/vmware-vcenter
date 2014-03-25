require 'json'
require 'asm/util'

module ASM
  module DeploymentTeardown

    def self.clean_deployment (id, logger=nil)
      data = JSON.parse(File.read(deployment_json_file(id)))
      names = self.get_deployment_certs((data['Deployment'] || {}))
      if names !=[]
        self.clean_deployment_certs(names)
        logger.debug("Deactivated nodes #{names.join(',')} from deployment id #{id}") if logger
        self.clean_puppetdb_nodes(names)
        logger.debug("Cleaned puppet certs #{names.join(',')} from deployment id #{id}") if logger
      end
    end

    # Call to puppet returns list of hots which look like 
    #  + "dell_iom-172.17.15.234" (SHA256) CF:EE:DB:CD:2A:45:17:99:E9:C0:4D:6D:5C:C4:F0:4F:9D:F1:B9:E5:1B:69:3D:99:C2:45:49:5B:0F:F0:08:83
    # this strips all the information and just returns array of host names: "dell_iom-172.17.15.234", "dell_...."
    def self.get_deployed_certs()
      certs_list = []
      results = ASM::Util.run_command_simple("sudo puppet cert list --all")
      unless results['exit_status'] == 0
        raise(Exception, "Call to puppet cert list all failed: \nstdout:#{results['stdout']}\nstderr:#{results['stderr']}\n")
      end
      rslt_str = results['stdout']
      cert_list_array = rslt_str.split('+')
      cert_list_array.delete_at(0)
      cert_list_array.each do |cert|
        certs_list.push(cert.slice(0..(cert.index('(SHA256)')-1)).gsub(/"/,'').strip)
      end
      certs_list
    end

    def self.clean_deployment_certs(certs)
      certs_string = certs.join(' ')
      results = ASM::Util.run_command_simple("sudo puppet cert clean #{certs_string}")
      unless results['exit_status'] == 0
        raise(Exception, "Call to puppet cert clean failed: \nstdout:#{results['stdout']}\nstderr:#{results['stderr']}\n")
      end
    end

    def self.clean_puppetdb_nodes(names)
      names_string = names.join(' ')
      results = ASM::Util.run_command_simple("sudo puppet node deactivate #{names_string}")
      unless results['exit_status'] == 0
        raise(Exception, "Call to puppet deactivate nodes failed: \nstdout:#{results['stdout']}\nstderr:#{results['stderr']}\n")
      end
    end

    def self.get_deployment_certs(data)
      agentless_image_types = ['vmware_esxi']
      cert_list = []
      comps = (data['serviceTemplate'] || {})['components'] || []
      ASM::Util.asm_json_array(comps).each do |c|
        if c['type'] == 'SERVER' or c['type'] == "VIRTUALMACHINE" 
          (c['resources'] || {}).each do |r|
            if r['id'] == 'asm::server'
              os_host_name = nil
              agent = true
              r['parameters'].each do |param|
                if param['id'] == 'os_host_name'               
                  os_host_name = param['value'] if param['id'] == 'os_host_name'
                end
                if param['id'] == 'os_image_type'
                  if agentless_image_types.include?(param['value'])
                    agent = false
                  end
                end
              end
              cert_list.push(ASM::Util.hostname_to_certname(os_host_name)) if os_host_name and agent
            end
          end
        end
      end
      cert_list
    end


    def self.deployment_json_file(id)
      deployment_dir = File.join(ASM.base_dir, id.to_s, 'deployment.json')
    end


  end
end
