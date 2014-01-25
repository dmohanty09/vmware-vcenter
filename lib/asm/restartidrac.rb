require 'pathname'
module_path = Pathname.new(__FILE__).parent
require "#{module_path}/checklcstatus"
require "#{module_path}/discoverswitch"
require "#{module_path}/reboot"

include REXML

class RestartIDRAC
  def initialize (devicehash, switchinfo)
        @devicehash = devicehash
        @switchinfo = switchinfo

  end

  def restartidrac(logger)
      ip = ""
      username = ""
      password = ""
      @devicehash.each do |key,value|
          if key == "idrac_ip"
              ip = value
          elsif key == "idrac_username"
              username = value
          elsif key == "idrac_password"
              password = value
          end
      end
      logger.debug "ip :: #{ip} username :: #{username} password :: #{password}"
      rebootidrac = Reboot.new(ip,username,password)
      resp =  rebootidrac.reboot(logger)
  end
end
