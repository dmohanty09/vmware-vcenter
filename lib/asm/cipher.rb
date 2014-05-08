require 'asm/util'
require 'aescrypt'
require 'base64'
require 'ostruct'
require 'sequel'
require 'yaml'

def database_config(filepath)
  @config ||= begin
    raise(ArgumentError, "Invalid filepath: #{filepath}") unless File.exists? filepath
    config = YAML.load_file(filepath)
    raise Error, "Invalid config: #{config}" unless config.is_a? ::Hash
    OpenStruct.new(config)
  end
end

def connect_database(conf)
  if RUBY_PLATFORM == 'java'
    require 'jdbc/postgres'
    Jdbc::Postgres.load_driver
    Sequel.connect("jdbc:postgresql://#{conf.host}/encryptionmgr?user=#{conf.username}&password=#{conf.password}")
  else
    require 'pg'
    Sequel.connect("postgres://#{conf.username}:#{conf.password}@#{conf.host}:#{conf.port}/encryptionmgr")
  end
end

module ASM
  module Cipher

    def self.db(config = nil)
      @db ||= begin
        config ||= database_config(ASM::Util::DATABASE_CONF)
        connect_database(config)
      end
    end

    def self.decrypt_string(id)
      e_string = get_encrypted_string(id)
      e_key = get_encryption_key(e_string[:encryptionmethodid])
      decrypt(e_key[:bytes], e_string[:encrypteddata])
    end

    def self.decrypt(key, string)
      result = AESCrypt.decrypt_data(Base64.decode64(string), Base64.decode64(key), nil, 'AES-128-CBC')
      result.slice(16..-1)
    end

    def self.get_encrypted_string(id)
      result = self.db['SELECT * FROM encryptedstring WHERE id = ?', id].first
      raise(ArgumentError, "Invalid encryption string id: '#{id}'") unless result.is_a? ::Hash
      result
    end

    def self.get_encryption_key(id)
      result = self.db['SELECT bytes FROM encryptionkey WHERE id = (SELECT key_id FROM encryptionmethod WHERE id = ?)', id].first
      raise(ArgumentError, "Invalid encryption key id: '#{id}'") unless result.is_a? ::Hash
      result
    end

    def self.credential_query
      @query ||= begin
        query = <<EOT
SELECT username, passwordid, domain, credtype, protocol,
       COALESCE(i.snmp_community_string_id, s.snmp_community_string_id)
         AS snmp_community_stringid
FROM credential AS c
       LEFT JOIN iom_credential AS i ON c.id = i.credential_id
       LEFT JOIN storage_credential AS s ON c.id = s.credential_id
WHERE id = ?
EOT

        query.lines.collect do |line|
          line.strip!
          line unless line.empty?
        end.compact.join(' ')
      end
    end

    def self.decrypt_credential(id)
      result = self.db[credential_query, id].first
      raise(ArgumentError, "Invalid credential id: '#{id}'") unless result.is_a? ::Hash
      ret = {}
      result.each do |key, val|
        if key.to_s =~ /^(.+?)_?id$/
          ret[$1.to_sym] = decrypt_string(val)
        else
          ret[key] = val
        end
      end
      OpenStruct.new(ret)
    end

  end
end
