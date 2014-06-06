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
    
    def self.prep_deployment_dir(data)
      id = data['id']
      begin
        dir = File.join(ASM::base_dir, id)
        raise 'Deployment directory not found for retry' unless File.directory?(dir)

        # Back up the current deployment directory
        ASM.logger.info('Backing up current deployment directory ...')
        ASM::UpdateDeployment.backup_directory(dir)
      end
    end

    def self.components_for_migration(service_deployment)
      components_for_migration = {}
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
          components_for_migration[component['type']] ||= []
          components_for_migration[component['type']].push(component)
        end
      end
      components_for_migration
    end
  end
end

