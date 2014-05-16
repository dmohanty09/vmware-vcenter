require 'puppet'
require 'hashie'
require 'inifile'

Puppet.initialize_settings unless Puppet.settings.global_defaults_initialized?

config = IniFile.load(Puppet[:config])
config['agent'] ||= {}
macaddress = Facter.value('macaddress')
raise(Exception, "Can not detect system macaddress.") unless macaddress
config['agent']['certname'] = "vm#{macaddress.gsub(':','')}"
config.save
