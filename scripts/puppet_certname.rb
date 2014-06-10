require 'puppet'
require 'hashie'
require 'inifile'
require 'fileutils'

Puppet.initialize_settings unless Puppet.settings.global_defaults_initialized?
# delete the old cert directory
FileUtils.rm_rf('c:\\programdata\\PuppetLabs\\puppet\\etc\\ssl')
config = IniFile.load(Puppet[:config])
config['agent'] ||= {}
macaddress = Facter.value('macaddress')
raise(Exception, "Can not detect system macaddress.") unless macaddress
config['main']['certname'] = "vm#{macaddress.gsub(':','').downcase}"
config['agent']['certname'] = "vm#{macaddress.gsub(':','').downcase}"
config.save