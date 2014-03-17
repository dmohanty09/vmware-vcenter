require 'json'
require 'asm/util'
require 'asm'
module ASM
  module PuppetCertManager

    def self.clean_deployment_certs(id)
      certs = self.get_deployment_certs(id)
      if certs != []
        certs_string = certs.join(' ')
        results = ASM::Util.run_command_simple("sudo puppet cert clean #{certs_string}")
        unless results['exit_status'] == 0
          raise(Exception, "Call to puppet cert clean failed: \nstdout:#{results['stdout']}\nstderr:#{results['stderr']}\n")
        end
        certs_string
      end
    end

    def self.get_deployment_certs(id)
      agentless_image_types = ['vmware_esxi']
      cert_list = []
      data = JSON.parse(File.read(deployment_json_file(id)))
      comps = ((data['Deployment'] || {})['serviceTemplate'] || {})['components']
      raise(Exception, "deployment json for #{id} has no components") unless comps
      ASM::Util.asm_json_array(comps).each do |c|
        if c['type'] == 'SERVER' or c['type'] == "VIRTUALMACHINE"
          (c['resources'] || {}).each do |r|
            if r['id'] == 'asm::server'
              os_host_name = nil
              agent        = true
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
              cert_list.push('agent-'+os_host_name) if os_host_name and agent
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
