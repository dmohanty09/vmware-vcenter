module ASM
  module Processor
    module Server

      #
      # takes a server hash and network hash from asm
      # and converts them into the expected asm::server
      # resource hash
      #
      def self.munge_hyperv_server(title, old_resources)

        resources = old_resources.dup 

        idrac_params = (resources['asm::idrac'] || {})[title]

        # if hyperv is on idrac, make some customizations
        if idrac_params
          if idrac_params['target_boot_device'] == 'SD'
            raise(Exception, 'HyperV does not work with target boot device SD')
          end
          idrac_params['enable_npar'] = false
          idrac_params['sysprofile']  = 'PerfOptimized'
        end

        # now munge some params!
        server_params = ((resources['asm::server'] || {})[title] || {}).dup

        # munge data that needs to go to unattended file
        installer_options = {}

        [
          'language',
          'keyboard',
          'product_key',
          'timezone',
          'ntp',
        ].each do |param|
          installer_options[param] = server_params.delete(param)
        end

        # I need to save the value from the GUI b/c I need to use it to pick the correct
        # unattended file
        installer_options['os_type'] =  server_params.delete('os_image_type')

        # munge data that needs to be availble when puppet configures
        # hyperv
        server_params['installer_options'] = installer_options

        puppet_classification_data = {'hyperv::config' => {}}

        [
	  'domain_name',
	  'fqdn',
	  'domain_admin_user',
	  'domain_admin_password',
	].each do |param|
          puppet_classification_data['hyperv::config'][param] = server_params.delete(param)
        end

        # now merge in network parameters
        net_params   = (resources['asm::esxiscsiconfig'] || {})[title]

        net_mapper = {
          'ip_address' => 'ip_address',
          'subnet'     => 'netmask',
          'primaryDns' => 'dns_server',
          'gateway'    => 'gateway'
        }

        (net_params || {}).each do |name, net_array|

          if ['private_cluster_network', 'live_migration_network', 'hypervisor_network'].include?(name)

            first_net = net_array.first
            param_prefix = name == 'hypervisor_network' ? 'converged_net' : name.sub(/_network$/, '')

            puppet_classification_data['hyperv::config'][ "#{param_prefix}_vlan_id"] = first_net['vlanId']

            net_mapper.each do |attr, puppet_param|
              param = "#{param_prefix}_#{puppet_param}"
              puppet_classification_data['hyperv::config'][param] = first_net['staticNetworkConfiguration'][attr]
            end

          end

          if name == 'storage_network'
            unless net_array.size == 2
              raise("Expected 2 iscsi interfaces for hyperv, only found #{net_array.size}")
            end
            first_net = net_array.first
            puppet_classification_data['hyperv::config']['iscsi_netmask']     =  first_net['staticNetworkConfiguration']['subnet']
            puppet_classification_data['hyperv::config']['iscsi_vlan_id']           =  first_net['vlanId']
            puppet_classification_data['hyperv::config']['iscsi_ip_addresses'] = []
            puppet_classification_data['hyperv::config']['iscsi_ip_addresses'].push(first_net['staticNetworkConfiguration']['ip_address'])
            puppet_classification_data['hyperv::config']['iscsi_ip_addresses'].push(net_array.last['staticNetworkConfiguration']['ip_address'])
          end

        end

        server_params['puppet_classification_data'] = puppet_classification_data

        server_params.delete('domain_admin_password_confirm')
        server_params['os_image_type']  = 'windows'
        server_params['razor_image']    = 'win_hyper_v'


        (resources['asm::server'] || {})[title] = server_params
        (resources['asm::idrac'] || {})[title]  = idrac_params

        resources
      end

    end
  end
end
