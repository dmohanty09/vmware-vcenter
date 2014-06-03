require 'asm'
require 'asm/util'
require 'asm/service_deployment'
require 'asm/update_deployment'
require 'asm/network_configuration'
require 'asm/processor/server'
require 'asm/razor'
require 'fileutils'
require 'json'
require 'logger'
require 'open3'
require 'rest_client'
require 'timeout'
require 'securerandom'
require 'yaml'
require 'asm/wsman'
require 'fileutils'
require 'asm/get_switch_information'
require 'uri'
require 'asm/discoverswitch'
require 'asm/cipher'
require 'asm/resource'

module ASM
  module ServiceMigrationDeployment
    def initialize(id)
      unless id
        raise(Exception, "Service Migration deployment must have an id")
      end
      @id = id
    rescue
      ASM.logger.info("In case there is any exception in backup of the file")
      ASM::UpdateDeployment.backup_directory(id)
    end
    
    def self.process_deployment_migration(data)
      id = data['id']
      begin
        dir = File.join(ASM::base_dir, id)
        raise 'Deployment directory not found for retry' unless File.directory?(dir)

        # Back up the current deployment directory
        ASM.logger.info("Backing up current deployment directory ...")
        backup = ASM::UpdateDeployment.backup_directory(dir)

        deployment_file = File.join(backup, 'deployment.json')
        data['migration'] = 'true'

        ASM.logger.info("Initiating the server migration")
        ASM.process_deployment(data)
      end
    end

    def self.components_for_miration(service_deployment)
      components_for_miration = {}
      if service_deployment['serviceTemplate']
        unless service_deployment['serviceTemplate']['components']
          logger.warn("service deployment data has no components")
        end
      else
        logger.warn("Service deployment data has no serviceTemplate defined")
      end

      components = ASM::Util.asm_json_array((service_deployment['serviceTemplate'] || {})['components'] || [])

      ASM.logger.debug("Found #{components.length} components")
      components.each do |component|
        ASM.logger.debug("Found component id #{component['id']}")
        resource_hash = ASM::Util.build_component_configuration(component, :decrypt => true )
        if resource_hash['asm::baseserver']
          ASM.logger.debug("Component #{component} has old server information")
          components_for_miration[component['type']] ||= []
          components_for_miration[component['type']].push(component)
        end
      end
      components_for_miration
    end
    

    
#    def process_migration_storage(component)
#      log("Processing storage component: #{component['id']}")
#
#      resource_hash = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)
#
#      process_storage = false
#      (resource_hash['compellent::createvol'] || {}).each do |title, params|
#        # Check if the volume has boot volume set to true
#        related_servers = find_related_components('SERVER', component)
#        boot_flag = resource_hash['compellent::createvol'][title]['boot']
#        if boot_flag
#          # There has to be only one related server, else raise error
#          unless related_servers.size == 1
#            raise(Exception, "Expected to find only one related server, found #{related_servers.size}")
#          end
#        end
#        configure_san = resource_hash['compellent::createvol'][title]['configuresan']
#        resource_hash['compellent::createvol'][title].delete('configuresan')
#        resource_hash['compellent::createvol'][title]['force'] = 'true'
#
#        related_servers.each do |server_comp|
#          wwpns = nil
#          wwpns ||= (get_specific_dell_server_wwpns(server_comp || []))
#          new_wwns = wwpns.compact.map {|s| s.gsub(/:/, '')}
#          resource_hash['compellent::createvol'][title]['wwn'] = new_wwns
#          server_servicetag = ASM::Util.cert2serial(server_comp['puppetCertName'])
#          if configure_san
#            resource_hash['compellent::createvol'][title]['servername'] = "ASM_#{server_servicetag}"
#          else
#            resource_hash['compellent::createvol'][title]['servername'] = ""
#          end
#
#          process_generic(
#          component['puppetCertName'],
#          resource_hash,
#          'device',
#          true,
#          nil,
#          component['asmGUID']
#          )
#        end
#        process_storage = true
#      end
#
#      # Process EqualLogic manifest file in case auth_type is 'iqnip'
#      network_configs = build_related_network_configs(component)
#      (resource_hash['asm::volume::equallogic'] || {}).each do |title, params|
#        if resource_hash['asm::volume::equallogic'][title]['auth_type'] == "iqnip"
#          iscsi_ipaddresses = network_configs.map do |network_config|
#            ips = network_config.get_static_ips('STORAGE_ISCSI_SAN')
#            raise("Expected 2 iscsi interfaces for hyperv, only found #{ips.size}") unless ips.size == 2
#            ips
#          end.flatten.uniq
#          logger.debug "iSCSI IP Address reserved for the deployment: #{iscsi_ipaddresses}"
#          server_template_iqnorip = resource_hash['asm::volume::equallogic'][title]['iqnorip']
#          logger.debug "server_template_iqnorip : #{server_template_iqnorip}"
#          if !server_template_iqnorip.nil?
#            logger.debug "Value of IP or IQN provided"
#            new_iscsi_iporiqn = server_template_iqnorip.split(',') + iscsi_ipaddresses
#          else
#            logger.debug "Value of IP or IQN not provided in service template"
#            new_iscsi_iporiqn = iscsi_ipaddresses
#          end
#          new_iscsi_iporiqn = new_iscsi_iporiqn.compact.map {|s| s.gsub(/ /, '')}
#          resource_hash['asm::volume::equallogic'][title]['iqnorip'] = new_iscsi_iporiqn
#        end
#      end
#
#      (resource_hash['netapp::create_nfs_export'] || {}).each do |title, params|
#        # TODO: Why is the variable called management_ipaddress if it is a list including nfs ips?
#        management_ipaddress = network_configs.map do |network_config|
#          # WAS: if name == 'hypervisor_network' or name == 'converged_network' or name == 'nfs_network'
#          # TODO: what network type is converged_network?
#          network_config.get_static_ips('HYPERVISOR_MANAGEMENT', 'FILESHARE')
#        end.flatten.uniq
#        logger.debug "NFS IP Address in host processing: #{management_ipaddress}"
#        if management_ipaddress.empty?
#          management_ipaddress = ['all_hosts'] # TODO: is this a magic value?
#          logger.debug "NFS IP Address list is empty: #{management_ipaddress}"
#        end
#        resource_hash['netapp::create_nfs_export'][title]['readwrite'] = management_ipaddress
#        resource_hash['netapp::create_nfs_export'][title]['readonly'] = ''
#
#        size_param = resource_hash['netapp::create_nfs_export'][title]['size']
#        if size_param.include?('GB')
#          resource_hash['netapp::create_nfs_export'][title]['size'] = size_param.gsub(/GB/,'g')
#        end
#        if size_param.include?('MB')
#          resource_hash['netapp::create_nfs_export'][title]['size'] = size_param.gsub(/MB/,'m')
#        end
#        if size_param.include?('TB')
#          resource_hash['netapp::create_nfs_export'][title]['size'] = size_param.gsub(/TB/,'t')
#        end
#
#        resource_hash['netapp::create_nfs_export'][title].delete('path')
#        resource_hash['netapp::create_nfs_export'][title].delete('nfs_network')
#        snapresv = resource_hash['netapp::create_nfs_export'][title]['snapresv']
#        resource_hash['netapp::create_nfs_export'][title]['snapresv'] = snapresv.to_s
#
#        # handling anon
#        resource_hash['netapp::create_nfs_export'][title].delete('anon')
#      end
#
#      if !process_storage
#        process_generic(
#        component['puppetCertName'],
#        resource_hash,
#        'device',
#        true,
#        nil,
#        component['asmGUID']
#        )
#      end
#    end
#
#
#    def self.process_migration_server(component)
#      log("Processing server component: #{component['puppetCertName']}")
#      cert_name = component['puppetCertName']
#
#      # In the case of Dell servers the cert_name should contain
#      # the service tag and we retrieve it here
#      serial_number = ASM::Util.cert2serial(cert_name)
#      is_dell_server = ASM::Util.dell_cert?(cert_name)
#      ASM.logger.debug "#{cert_name} -> #{serial_number}"
#      ASM.logger.debug "Is #{cert_name} a dell server? #{is_dell_server}"
#      resource_hash = {}
#      server_vlan_info = {}
#      deviceconf = nil
#      inventory = nil
#      os_host_name = nil
#      resource_hash = ASM::Util.build_component_configuration(component, :decrypt => decrypt?)
#      if !is_dell_server && resource_hash['asm::idrac']
#        ASM.logger.debug "ASM-1588: Non-Dell server has an asm::idrac resource"
#        ASM.logger.debug "ASM-1588: Stripping it out."
#        resource_hash.delete('asm::idrac')
#      end
#
#      #Flag an iSCSI boot from san deployment
#      if is_dell_server and resource_hash['asm::idrac'][resource_hash['asm::idrac'].keys[0]]['target_boot_device'] == 'iSCSI'
#        @bfs = true
#      else
#        @bfs = false
#      end
#
#      # Server Migration - Reset for the original server
#      if !resource_hash['asm::oldserver']
#        raise(Exception,"Old Server certname not avaialble, cannot proceed with migration")
#      end
#
#      old_server_certname = resource_hash['asm::oldserver'].keys[0]['id']
#      log("Process IO Identities cleanup on ")
#      cleanup_server(resource_hash)
#
#      if is_dell_server && resource_hash['asm::idrac']
#        if resource_hash['asm::idrac'].size != 1
#          msg = "Only one iDrac configuration allowed per server; found #{resource_hash['asm::idrac'].size} for #{serial_number}"
#          ASM.logger.error(msg)
#          raise(Exception, msg)
#        end
#
#        title = resource_hash['asm::idrac'].keys[0]
#        params = resource_hash['asm::idrac'][title]
#        deviceconf = ASM::Util.parse_device_config(cert_name)
#        inventory = ASM::Util.fetch_server_inventory(cert_name)
#        params['nfsipaddress'] = ASM::Util.get_preferred_ip(deviceconf[:host])
#        params['nfssharepath'] = '/var/nfs/idrac_config_xml'
#        params['servicetag'] = inventory['serviceTag']
#        params['model'] = inventory['model'].split(' ').last.downcase
#        if network_config
#          params['network_configuration'] = network_config.to_hash
#        end
#        params['before'] = []
#
#        #Process a BFS Server Component
#        if params['target_boot_device'] == 'iSCSI'
#          ASM.logger.debug "Processing iSCSI Boot From San configuration"
#          #Flag Server Component as BFS
#          @bfs = true
#          #Get Network Configuration
#          params['network_configuration'] = build_network_config(component).to_hash
#          #Find first related storage component
#          storage_component = find_related_components('STORAGE',component)[0]
#          #Identify Boot Volume
#          boot_volume = storage_component['resources'].detect{|r|r['id']=='asm::volume::equallogic'}['parameters'].detect{|p|p['id']=='title'}['value']
#          #Get Storage Facts
#          ASM::Util.run_puppet_device!(storage_component['puppetCertName'])
#          params['target_iscsi'] = ASM::Util.find_equallogic_iscsi_volume(storage_component['asmGUID'],boot_volume)['TargetIscsiName']
#          params['target_ip'] = ASM::Util.find_equallogic_iscsi_ip(storage_component['puppetCertName'])
#          resource_hash.delete("asm::server")
#        end
#
#        if resource_hash['asm::server']
#          params['before'].push("Asm::Server[#{cert_name}]")
#        end
#        if resource_hash['file']
#          params['before'].push("File[#{cert_name}]")
#        end
#        if resource_hash['file']
#          params['']
#        end
#      end
#    end
 
  end
end

