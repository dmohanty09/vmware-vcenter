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
    Sequel.connect("postgres://#{conf.username}:#{conf.password}@#{conf.host}:#{db_conf['port']}/encryptionmgr")
  end
end

# TODO: unless someone else have better idea how to mock this:
DB = connect_database(database_config(ASM::Util::DATABASE_CONF)) unless ENV['MOCK_SEQUEL']

module ASM
  module Cipher
    def self.decrypt_string(id)
      e_string = get_string(id)
      e_key    = get_key(e_string[:encryptionmethodid])
      d_string = AESCrypt.decrypt_data(Base64.decode64(e_string[:encrypteddata]),Base64.decode64(e_key[:bytes]),nil,'AES-128-CBC')
      d_string.slice!(0,16)
      d_string
    end
    def self.get_string(id)
      DB['SELECT * FROM encryptedstring WHERE id = ?', id].first
    end
    def self.get_key(key_id)
      DB['SELECT bytes FROM encryptionkey WHERE id = (SELECT key_id FROM encryptionmethod WHERE id = ?)', key_id].first
    end
  end
end
