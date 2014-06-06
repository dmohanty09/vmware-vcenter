# WARNING: This does not work properly. Just use the db/schema.sql file to
# rebuild the db

Sequel.migration do

  up do
    create_table(:deployments, :ignore_index_errors=>true) do
      primary_key :id
      String :asm_guid, :size=>255, :null=>false
      String :name, :size=>255, :null=>false
      DateTime :update_time, :null=>false

      index [:asm_guid], :name=>:deployments_asm_guid_key, :unique=>true
    end

    create_table(:executions, :ignore_index_errors=>true) do
      primary_key :id
      foreign_key :deployment_id, :deployments, :null=>false, :key=>[:id], :on_delete=>:cascade
      Integer :order, :null=>false
      String :status, :size=>255, :null=>false
      DateTime :start_time, :default=>Sequel::CURRENT_TIMESTAMP, :null=>false
      DateTime :end_time
      DateTime :update_time, :null=>false

      index [:deployment_id, :order], :name=>:executions_deployment_id_order_key, :unique=>true
    end

    create_table(:components) do
      primary_key :id
      foreign_key :execution_id, :executions, :null=>false, :key=>[:id], :on_delete=>:cascade
      String :asm_guid, :size=>255, :null=>false
      String :component_uuid, :size=>255, :null=>false
      String :name, :size=>255, :null=>false
      String :type, :size=>255, :null=>false
      String :status, :size=>255, :null=>false
      String :message, :text=>true, :null=>false
      DateTime :start_time, :default=>Sequel::CURRENT_TIMESTAMP, :null=>false
      DateTime :end_time
      DateTime :update_time, :null=>false
    end

    create_table(:execution_log_entries) do
      foreign_key :execution_id, :executions, :null=>false, :key=>[:id]
      foreign_key :component_id, :components, :key=>[:id]
      String :level, :default=>"INFO", :size=>255, :null=>false
      String :message, :text=>true, :null=>false
      DateTime :timestamp, :default=>Sequel::CURRENT_TIMESTAMP, :null=>false
    end

    run <<EOT
CREATE OR REPLACE FUNCTION "set_update_timestamp"()
  RETURNS TRIGGER AS '
BEGIN
  NEW.update_time = NOW();
  RETURN NEW;
END;
' LANGUAGE 'plpgsql' IMMUTABLE CALLED ON NULL INPUT SECURITY INVOKER;

CREATE TRIGGER "trg_set_deployments_update_time" BEFORE INSERT OR UPDATE
ON deployments FOR EACH ROW
EXECUTE PROCEDURE "public"."set_update_timestamp"();

CREATE TRIGGER "trg_set_executions_update_time" BEFORE INSERT OR UPDATE
ON executions FOR EACH ROW
EXECUTE PROCEDURE "public"."set_update_timestamp"();

CREATE TRIGGER "trg_set_components_update_time" BEFORE INSERT OR UPDATE
ON components FOR EACH ROW
EXECUTE PROCEDURE "public"."set_update_timestamp"();

EOT
  end

  down do
    run <<EOT
DROP TRIGGER "trg_set_deployments_update_time";
DROP TRIGGER "trg_set_executions_update_time";
DROP TRIGGER "trg_set_components_update_time";

EOT

    drop_table(:execution_log_entries)
    drop_table(:components)
    drop_table(:executions)
    drop_table(:deployments)
  end
end
