require "sequel"
require "aescrypt"
require 'asm/util'
db_conf = YAML.load_file(ASM::Util::DATABASE_CONF)
if RUBY_PLATFORM == "java"
  require 'jdbc/postgres'
  Jdbc::Postgres.load_driver
  DB = Sequel.connect("jdbc:postgresql://#{db_conf['host']}/encryptionmgr?user=#{db_conf['username']}&password=#{db_conf['password']}")
else
  require "pg"
  DB = Sequel.connect("postgres://#{db_conf['username']}:#{db_conf['password']}@#{db_conf['host']}:#{db_conf['port']}/encryptionmgr")
end

module ASM
  module Cipher
    def self.decrypt_string(id)
      e_string = get_string(id)
      e_key    = get_key(e_string[:encryptionmethodid])
      d_string = AESCrypt.decrypt_data(Base64.decode64(e_string[:encrypteddata]),Base64.decode64(e_key[:bytes]),nil,"AES-128-CBC")
      d_string.slice!(0,16)
      d_string
    end
    def self.get_string(id)
      DB["SELECT * FROM encryptedstring WHERE id = ?", id].first
    end
    def self.get_key(key_id)
      DB["SELECT bytes FROM encryptionkey WHERE id = (SELECT key_id FROM encryptionmethod WHERE id = ?)", key_id].first
    end
  end
end
