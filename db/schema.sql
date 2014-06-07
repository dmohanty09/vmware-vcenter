-- Currently building 001_create_base_schema.rb from this file using:
--
-- dropdb -h 127.0.0.1 -U orion asm_dev && createdb -h 127.0.0.1 -U orion asm_dev  && cat db/schema.sql | psql -h 127.0.0.1 -U orion asm_dev

-- NOTE: the migration ruby stuff doesn't work, just use the above
-- sequel -d 'jdbc:postgresql:asm_dev?user=orion&password=Password123$' > db/migrate/001_create_base_schema.rb
-- OR (MRI ruby): sequel -d 'postgres://orion:Password123$@localhost/asm_dev' > db/migrate/001_create_base_schema.rb

CREATE FUNCTION "set_update_timestamp"()
  RETURNS TRIGGER AS '
BEGIN
  NEW.update_time = NOW();
  RETURN NEW;
END;
' LANGUAGE 'plpgsql' IMMUTABLE CALLED ON NULL INPUT SECURITY INVOKER;

-- A service deployment
CREATE SEQUENCE deployments_id_seq;
CREATE TABLE deployments
(
  id          INTEGER                  NOT NULL PRIMARY KEY DEFAULT nextval(
      'deployments_id_seq'),
  asm_guid    CHARACTER VARYING(255)   NOT NULL UNIQUE,
  "name"      CHARACTER VARYING(255)   NOT NULL,
  update_time TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TRIGGER "trg_set_deployments_update_time" BEFORE INSERT OR UPDATE
ON deployments FOR EACH ROW
EXECUTE PROCEDURE "public"."set_update_timestamp"();

-- an execution of a deployment. order of 0 is always the most recent execution
CREATE SEQUENCE executions_id_seq;
CREATE TABLE executions
(
  id            INTEGER                  NOT NULL PRIMARY KEY DEFAULT nextval(
      'executions_id_seq'),
  deployment_id INTEGER                  NOT NULL REFERENCES deployments (id) ON DELETE CASCADE,
  "order"       INTEGER                  NOT NULL,
  status        CHARACTER VARYING(255)   NOT NULL,
  message       TEXT,
  start_time    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  end_time      TIMESTAMP WITH TIME ZONE,
  update_time   TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TRIGGER "trg_set_executions_update_time" BEFORE INSERT OR UPDATE
ON executions FOR EACH ROW
EXECUTE PROCEDURE "public"."set_update_timestamp"();

-- A component in a service deployment execution
-- NOTE: asm_guid may be null for VMs, apps
CREATE SEQUENCE components_id_seq;
CREATE TABLE components
(
  id             INTEGER                  NOT NULL PRIMARY KEY DEFAULT nextval(
      'components_id_seq'),
  execution_id   INTEGER                  NOT NULL REFERENCES executions (id) ON DELETE CASCADE,
  asm_guid       CHARACTER VARYING(255),
  component_uuid CHARACTER VARYING(255)   NOT NULL,
  "name"         CHARACTER VARYING(255)   NOT NULL,
  type           CHARACTER VARYING(255)   NOT NULL,
  status         CHARACTER VARYING(255)   NOT NULL,
  message        TEXT,
  start_time     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  end_time       TIMESTAMP WITH TIME ZONE,
  update_time    TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE TRIGGER "trg_set_components_update_time" BEFORE INSERT OR UPDATE
ON components FOR EACH ROW
EXECUTE PROCEDURE "public"."set_update_timestamp"();

-- A user-facing log entry. Component id is optional, if not specified the
-- message is applicable to the execution as a whole
CREATE TABLE execution_log_entries
(
  execution_id INTEGER                  NOT NULL REFERENCES executions (id) ON DELETE CASCADE,
  component_id INTEGER REFERENCES components (id) ON DELETE CASCADE,
  level        CHARACTER VARYING(255)   NOT NULL DEFAULT 'INFO',
  message      TEXT                     NOT NULL,
  timestamp    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
