require 'puppet'
require 'hashie'
require 'inifile'
require 'fileutils'
require 'rbconfig'

Puppet.initialize_settings unless Puppet.settings.global_defaults_initialized?
# delete the old cert directory

if !Config::CONFIG["arch"].include?('linux')
  # Windows platform
  sslfiledir = 'c:\\programdata\\PuppetLabs\\puppet\\etc\\ssl'
  verification_filename = 'c:\\programdata\\puppet_verification_run.txt'
  if !File.file?(verification_filename)
    puts "Running for the first time"
    FileUtils.rm_rf(sslfiledir)
    FileUtils.touch(verification_filename)
  end
else
  sslfiledir = '/var/lib/puppet/ssl'
  verification_filename = '/var/lib/puppet_verification_run.txt'
  if !File.file?(verification_filename)
    puts "Running for the first time"
    FileUtils.rm_rf(sslfiledir)
    FileUtils.touch(verification_filename)
  end
end


config = IniFile.load(Puppet[:config])
config['agent'] ||= {}
macaddress = Facter.value('macaddress')
raise(Exception, "Can not detect system macaddress.") unless macaddress
config['main']['certname'] = "vm#{macaddress.gsub(':','').downcase}"
config['agent']['certname'] = "vm#{macaddress.gsub(':','').downcase}"
config.save
abort
