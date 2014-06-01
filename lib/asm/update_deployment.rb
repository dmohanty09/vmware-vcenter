require 'fileutils'
require 'asm'
require 'asm/util'
require 'rest_client'

module ASM
  module UpdateDeployment
    def self.backup_directory(dir)

      # Backups are numbered directories, where 1 is the newest
      n = 1
      last_backup_no = nil
      test_dir = File.join(dir, n.to_s)
      while File.exists?(test_dir)
        last_backup_no = n
        n = n + 1
        test_dir = File.join(dir, n.to_s)
      end

      if last_backup_no
        # Shuffle the backups up by one
        last_backup_no.downto(1).each do |n|
          curr_dir = File.join(dir, n.to_s)
          next_dir = File.join(dir, (n + 1).to_s)
          File.rename(curr_dir, next_dir)
        end
      end

      # Create the new backup directory
      backup_dir = File.join(dir, '1')
      FileUtils.mkdir(backup_dir)
      
      # Move everything except for backup directories into backup_dir
      Dir.foreach(dir) do |fname|
        # Ignore backup directories (number), . and ..
        unless fname =~ /^[.0-9]+$/
          curr = File.join(dir, fname)
          new = File.join(backup_dir, fname)
          File.rename(curr, new)
        end
      end

      backup_dir
    end

    def self.backup_deployment_dirs(deployment_id, deployment, debug_deployment = false)
      dir = File.join(ASM::base_dir, deployment_id)
      raise 'Deployment directory not found for retry' unless File.directory?(dir)

      # Back up the current deployment directory
      ASM.logger.info("Backing up current deployment directory ...")
      backup = backup_directory(dir)
      
      deployment_file = File.join(backup, 'deployment.json')
      if debug_deployment == true
        deployment['debug'] = 'true'
      end
      deployment['retry'] = 'true'
    end
  end
end
