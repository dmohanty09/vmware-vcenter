require 'hashie'

module ASM
  module Data

    class NotFoundException < StandardError;
    end
    class NotFoundException < StandardError;
    end
    class NoDeployment < StandardError;
    end
    class NoExecution < StandardError;
    end
    class InvalidStatus < StandardError;
    end
    class InvalidLogLevel < StandardError;
    end
    class UpdateFailed < StandardError;
    end
    class InvalidComponentException < StandardError;
    end

    class Deployment

      VALID_STATUS_LIST = %w(in_progress complete error)
      TERMINAL_STATUS_LIST = %w(complete error)

      VALID_LOG_LEVEL_LIST = %w(debug info warn error)

      attr_accessor :id
      attr_accessor :execution_id
      attr_accessor :component_ids # map of component uuids to ids
      attr_reader :db

      # Set the status of all in_progress deployments to failed. Intended to
      # be used across reboots where we know that no deployments are running.
      # That way in the event of power outage we can mark all the in_progress
      # deployments as failed so the user can go and delete them
      def self.mark_in_progress_failed(db, logger = nil)
        query = <<EOT
SELECT d.id AS deployment_id, "name", e.id AS "execution_id"
    FROM deployments AS d JOIN executions AS e ON d.id = e.deployment_id
    WHERE e.status = 'in_progress'
EOT
        db.transaction do
          db[query].each do |row|
            msg = "Marking deployment #{row[:name]} ##{row[:deployment_id]} as error"
            logger.info(msg) if logger
            db[:executions].where(:id => row[:execution_id]).update(
                :status => 'error', :message => 'Deployment aborted due to reboot')
          end
        end
      end

      def initialize(db)
        @db = db
      end

      # Creates a database entry if it doesn't exist, raises an exception otherwise
      def create(asm_guid, name)
        self.id = db[:deployments].insert(:asm_guid => asm_guid, :name => name)
      end

      # Loads a deployment from db; raises an exception if a previous deployment
      # has already been created or loaded
      def load(asm_guid)
        row = db.from(:deployments).where(:asm_guid => asm_guid).first
        raise NotFoundException unless row
        self.id = row[:id]
        row = db.from(:executions).where(:deployment_id => id).first
        if row
          self.execution_id = row[:id]
        end
      end

      def create_execution(deployment_data)
        db.transaction do
          db['UPDATE executions SET "order" = "order" + 1 WHERE deployment_id = ?', id].update
          row = {:deployment_id => id, :order => 0, :status => 'in_progress'}
          self.execution_id = db[:executions].insert(row)
          self.component_ids = {}
          deployment_data['serviceTemplate']['components'].each do |comp|
            row = {:execution_id => execution_id,
                   :asm_guid => comp['asmGUID'],
                   :component_uuid => comp['id'],
                   :name => comp['name'],
                   :type => comp['type'],
                   :status => 'in_progress'}
            component_ids[comp['id']] = db[:components].insert(row)
          end
        end
      end

      # Returns structured data intended for direct rendering to REST call
      #
      # Pass order = 0 to get the most recent, 1 to get 2nd most, etc.
      # Pass nothing to get the last execution created on this object
      def get_execution(order = nil)
        execution_query = <<EOT
SELECT e.id AS "execution_id", asm_guid AS "id", "name", "status", "message", start_time, end_time
    FROM deployments AS d JOIN executions AS e ON d.id = e.deployment_id
EOT
        if order
          execution_query = execution_query + ' WHERE d.id = ? AND e.order = ?'
        else
          raise NoExecution unless execution_id
          execution_query = execution_query + ' WHERE d.id = ? AND e.id = ?'
        end

        components_query = <<EOT
SELECT component_uuid AS "id", "asm_guid", "name", "type", "status", "message",
       "start_time", "end_time"
    FROM components
    WHERE execution_id = ?
    ORDER BY "type", "name"
EOT
        ret = nil
        db.transaction do
          execution_selector = order ? order : execution_id
          ret = db[execution_query, id, execution_selector].first
          unless ret
            raise(NotFoundException, "No execution #{execution_selector} for deployment #{id}")
          end
          ret['components'] = []
          db[components_query, ret[:execution_id]].each do |component|
            ret['components'].push(component)
          end
        end
        Hashie::Mash.new(ret)
      end

      def set_status(status)
        if status.is_a?(Symbol)
          status = status.to_s
        end
        raise NoExecution unless execution_id
        raise InvalidStatus unless VALID_STATUS_LIST.include?(status)
        query = if TERMINAL_STATUS_LIST.include?(status)
                  'UPDATE executions SET status = ?, end_time = NOW() WHERE id = ?'
                else
                  'UPDATE executions SET status = ? WHERE id = ?'
                end

        unless db[query, status, execution_id].update == 1
          msg = "Failed to set deployment #{id} execution #{execution_id} status to #{status}"
          raise(UpdateFailed, msg)
        end
      end

      def get_component_id(component_uuid)
        component_ids[component_uuid] or raise(InvalidComponentException, "No such component id: #{component_uuid}")
      end

      def set_component_status(component_uuid, status)
        if status.is_a?(Symbol)
          status = status.to_s
        end
        raise NoExecution unless execution_id
        raise(InvalidStatus, "Not a valid component status: #{status}") unless VALID_STATUS_LIST.include?(status)
        component_id = get_component_id(component_uuid)
        query = if TERMINAL_STATUS_LIST.include?(status)
                  'UPDATE components SET status = ?, end_time = NOW() WHERE id = ? AND execution_id = ?'
                else
                  'UPDATE components SET status = ? WHERE id = ? AND execution_id = ?'
                end

        unless db[query, status, component_id, execution_id].update == 1
          msg = "Failed to set component #{component_id} execution #{execution_id} status to #{status}"
          raise(UpdateFailed, msg)
        end
      end

      # Creates a user-facing log message. Also updates the message field
      # on either the component or execution with the latest message
      def log(level, message, options = {})
        if level.is_a?(Symbol)
          level = level.to_s
        end
        raise NoExecution unless execution_id
        raise(InvalidLogLevel, "Not a valid log level: #{level}") unless VALID_LOG_LEVEL_LIST.include?(level)
        component_id = if options[:component_id]
                         get_component_id(options[:component_id])
                       end
        db.transaction do
          row = {:execution_id => execution_id, :component_id => component_id,
                 :level => level, :message => message}
          db[:execution_log_entries].insert(row)
          data_set = if component_id
                       db[:components].where(:id => component_id, :execution_id => execution_id)
                     else
                       db[:executions].where(:id => execution_id)
                     end
          unless data_set.update(:message => message) == 1
            raise(UpdateFailed, "Failed to update execution #{execcution_id} status to #{status}")
          end
        end
      end

      def get_logs(options = {})
        raise NoExecution unless execution_id
        component_id = if options[:component_id]
                         get_component_id(options[:component_id])
                       end
        where = {:execution_id => execution_id}
        if component_id
          where[:component_id] = component_id
        end
        db[:execution_log_entries].where(where).order(:timestamp).collect do |log|
          Hashie::Mash.new(log)
        end
      end

      def delete
        raise NoDeployment unless id
        db.from(:deployments).where(:id => id).delete
      end

    end
  end
end
