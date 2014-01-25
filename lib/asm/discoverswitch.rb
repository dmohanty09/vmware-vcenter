=begin
  initiate discovery for the switches
=end

require 'pathname'

class Discoverswitch
  DEVICE_CONF_DIR='/etc/puppetlabs/puppet/devices'

  def initialize (switchinfo)
    @switchinformation = switchinfo
  end

  def discoverswitch(logger)
    #iterating hash
    @switchinformation.each do |nodename,devicehash|
      conf_file = File.join(DEVICE_CONF_DIR, "#{nodename}.conf")
      logger.debug "conf_file :: #{conf_file}"
      logger.debug "Initiating puppet discovery for node #{nodename}"
      response = `sudo puppet device --deviceconfig "#{conf_file}" --debug `
    end
    return true
  end

end

