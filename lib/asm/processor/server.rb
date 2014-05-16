require 'asm/util'
require 'asm/network_configuration'

module ASM
  module Processor
    module Server

      #
      # takes a server hash and network hash from asm
      # and converts them into the expected asm::server
      # resource hash
      #
      def self.munge_hyperv_server(title, old_resources, target_ip, vol_names, logger, disk_part_flag, storage_type = 'iscsi', iscsi_fabric = "Fabric A")

        resources = old_resources.dup 

        idrac_params = (resources['asm::idrac'] || {})[title]

        # if hyperv is on idrac, make some customizations
        if idrac_params
          if idrac_params['target_boot_device'] == 'SD'
            raise(Exception, 'HyperV does not work with target boot device SD')
          end
          idrac_params['enable_npar'] = false
          idrac_params['system_profile']  = 'PerfOptimized'
        end

        # now munge some params!
        server_params = ((resources['asm::server'] || {})[title] || {}).dup

        server_params['cert_name'] = ASM::Util.hostname_to_certname(server_params['os_host_name'].split('.').first)

        # munge data that needs to go to unattended file
        installer_options = {}

        [
          'language',
          'keyboard',
          'product_key',
          'timezone',
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
	  'ntp'
	].each do |param|
          puppet_classification_data['hyperv::config'][param] = server_params.delete(param)
        end

        puppet_classification_data['hyperv::config']['iscsi_target_ip_address'] = target_ip
        puppet_classification_data['hyperv::config']['iscsi_volumes'] = vol_names

        # now merge in network parameters
        net_params   = (resources['asm::esxiscsiconfig'] || {})[title]
          
        network_config = ASM::NetworkConfiguration.new(net_params['network_configuration'], logger)
        management_network = network_config.get_network('HYPERVISOR_MANAGEMENT')
        migration_network = network_config.get_network('HYPERVISOR_MIGRATION')
        private_network = network_config.get_network('HYPERVISOR_CLUSTER_PRIVATE')

        net_mapper = {
          'ipAddress' => 'ip_address',
          'subnet'     => 'netmask',
          'gateway'    => 'gateway'
        }

        [management_network, migration_network, private_network].each do |network|

            param_prefix = name.sub(/_network$/, '')

            param_prefix = "converged_net" if network['type'] == 'HYPERVISOR_MANAGEMENT'
            param_prefix = "live_migration" if network['type'] == 'HYPERVISOR_MIGRATION'
            param_prefix = "cluster_private" if network['type'] == 'HYPERVISOR_CLUSTER_PRIVATE'

            puppet_classification_data['hyperv::config'][ "#{param_prefix}_vlan_id"] = network['vlanId']

            net_mapper.each do |attr, puppet_param|
              param = "#{param_prefix}_#{puppet_param}"
              puppet_classification_data['hyperv::config'][param] = network['staticNetworkConfiguration'][attr]
            end

            if network['type'] == 'HYPERVISOR_MANAGEMENT'
              puppet_classification_data['hyperv::config']['converged_net_dns_server'] = network['staticNetworkConfiguration']['primaryDns']
            end

        end
        
        storage_networks = network_config.get_networks('STORAGE_ISCSI_SAN')
        if storage_type == 'iscsi'
          unless storage_networks.size == 2
            raise("Expected 2 iscsi interfaces for hyperv, only found #{storage_networks.size}")
          end
          first_net = storage_networks[0]
          second_net = storage_networks[1]
          puppet_classification_data['hyperv::config']['iscsi_netmask']     =  first_net['staticNetworkConfiguration']['subnet']
          puppet_classification_data['hyperv::config']['iscsi_vlan_id']           =  first_net['vlanId']
          puppet_classification_data['hyperv::config']['iscsi_ip_addresses'] = []
          puppet_classification_data['hyperv::config']['iscsi_ip_addresses'].push(first_net['staticNetworkConfiguration']['ipAddress'])
          puppet_classification_data['hyperv::config']['iscsi_ip_addresses'].push(second_net['staticNetworkConfiguration']['ipAddress'])
          puppet_classification_data['hyperv::config']['iscsi_fabric'] = iscsi_fabric
        end

        puppet_classification_data['hyperv::config']['hyperv_diskpart'] = disk_part_flag
        if storage_type == 'fc'
          puppet_classification_data['hyperv::config']['pod_type'] = 'AS1000'
        end

        server_params['puppet_classification_data'] = puppet_classification_data

        server_params.delete('domain_admin_password_confirm')
        server_params['os_image_type']  = server_params['os_image_type'] || 'windows'

        (resources['asm::server'] || {})[title] = server_params
        (resources['asm::idrac'] || {})[title]  = idrac_params

        resources
      end

      def self.munge_bfs_server(resource_hash, params)
        params['network_configuration'] = resource_hash['asm::esxiscsiconfig'][resource_hash['asm::esxiscsiconfig'].keys[0]]['network_configuration']
      end

    end
  end

end
