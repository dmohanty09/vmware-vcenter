require 'json'
require 'asm/util'

module ASM
  module DeploymentTeardown

    def self.clean_deployment (id, logger=nil)
      data = JSON.parse(File.read(deployment_json_file(id)))
      names = self.get_deployment_certs(data)
      if names !=[]
        ASM.unblock_hostlist(names)
        self.clean_deployment_certs(names)
        logger.debug("Deactivated nodes #{names.join(',')} from deployment id #{id}") if logger
        self.clean_puppetdb_nodes(names)
        logger.debug("Cleaned puppet certs #{names.join(',')} from deployment id #{id}") if logger
      end
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
          ASM::Util.asm_json_array(c['resources'] || {}).each do |r|
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

    def self.get_previous_deployment_certs(deployment_id)
      old_certs = []
      previous_dirs = Dir.entries(File.join(ASM.base_dir, deployment_id)).select{ |dir| dir.match(/^[0-9]+$/) }
      previous_dirs.each do |pd|
        old_deployment = JSON.parse(File.read(deployment_json_file("#{deployment_id}/#{pd}")))
        old_certs << get_deployment_certs(old_deployment)
      end
      old_certs.flatten.uniq
    end

    def self.deployment_json_file(id)
      deployment_dir = File.join(ASM.base_dir, id.to_s, 'deployment.json')
    end


  end
end
