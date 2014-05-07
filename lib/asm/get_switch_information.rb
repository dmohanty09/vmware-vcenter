=begin
     This class will provide the information of the swtich and the connected port information
     support is added for the rack and the blade server

     TODO: Need to extend the support for the SAN server (Brocade)
=end

require 'pp'
require 'asm/discoverswitch'
require 'asm/rack_server_switch_information'
require 'asm/blade_server_switch_information'
require 'asm/san_switch_information'
require 'asm/wsman'

class Get_switch_information
  def initialize ()
    # Check the blade server type
    #@serverinformation= serverinfo
    #@switchinformation = switchinfo
  end

  def get_info(ser_info,sw_info,logger,server_nic_type=nil)
    switchinfolist = []
    switchinfohash = {}
    ser_info.each do |nodename,sinfo|
      sinfo.each do |key,value|
        if key == 'bladetype'
          bladetype = value
          if bladetype == "rack"
            switchinfohash = rack_server_switch_info(nodename,sinfo,sw_info,logger)
          else
            switchinfohash = blade_server_switch_info(nodename,sinfo,sw_info,logger,server_nic_type)
            if switchinfohash.length() > 0
              switchinfohash.keys().each do |macaddress|
              end
            end
          end
        end
      end
      switchinfolist.push(switchinfohash)
    end
    return switchinfolist
  end
  
  def get_san_info(ser_info,sw_info,wwpns, compellent_contollers, logger)
    switchinfolist = []
    switchinfohash = {}
    ser_info.each do |nodename,sinfo|
      switchinfohash = san_switch_info(nodename,sinfo,sw_info,wwpns,compellent_contollers,logger)
      logger.debug"switchinfohash: #{switchinfohash}"
      switchinfolist.push(switchinfohash)
      logger.debug"switchinfolist: #{switchinfolist}"
    end
    return switchinfolist
  end
  

  def blade_server_switch_info(nname,server,swinfo,logger,server_nic_type)
    bladeObj=Blade_server_switch_information.new(nname,server,swinfo)
    serverinformation=bladeObj.identify_switch_ports(swinfo,logger,server_nic_type)
    pp serverinformation
    return serverinformation
  end

  def san_switch_info(nname,server,swinfo,wwpns,compellent_contollers, logger)
    bladeObj=San_switch_information.new(nname,server,swinfo)
    serverinformation=bladeObj.identify_switch_ports(compellent_contollers,logger)
    servermacaddress=bladeObj.search_server_Macaddress(wwpns,compellent_contollers,logger)
    return servermacaddress
  end

  def rack_server_switch_info(nname,sinfo,switchinfo,logger)
    rackObj=Rack_server_switch_information.new(nname,sinfo,switchinfo)
    serverinformation=rackObj.identify_switch_ports(logger)
    servermacaddress=rackObj.search_server_Macaddress(logger)
    # Check if all the
    server_mac_address_count=sinfo["mac_addresses"].length()
    if servermacaddress.keys.count != server_mac_address_count
      logger.debug "Server #{nname} is not updated, need to run the discovery for these"
      # Reboot the server
      endpoint = { 
        :host => sinfo['idrac_ip'],
        :user => sinfo['idrac_username'],
        :password => sinfo['idrac_password']
      }
      ASM::WsMan.reboot(endpoint, logger)
      sleep(60)
      # Initiate the discovery of the switches
      discoverallswitch = Discoverswitch.new(switchinfo)
      resp = discoverallswitch.discoverswitch(logger)
      logger.debug "resp :: #{resp}"
      # Need to run the fact search once again
      serverinfo=rackObj.identify_switch_ports(logger)
      servermacaddress=rackObj.search_server_Macaddress(logger)
      server_mac_address_count=sinfo["mac_addresses"].length()
      if servermacaddress.keys.count != server_mac_address_count
        logger.debug "#{nname}:Not able to identify the server information on any switch, seems it is not connected"
      end
    end

    return servermacaddress
  end

end

#serverinfo={ "7DF8ZV1" => { "mac_addresses" => '00:0A:F7:06:BC:C0,00:0A:F7:06:BC:C2', "bladetype" => 'rack' , "servermodel" => 'R720', "idrac_ip" => '10.128.46.107', "idrac_username" => 'root', "idrac_password" => 'calvin'} }
#
#switchinfo={ "dell_ftos-10.128.46.101" => { "device_type" => "dell_ftos", "connection_url" => "ssh://admin:password@10.128.46.101"}, "dell_ftos-10.128.46.102" => { "device_type" => "dell_ftos", "connection_url" => "ssh://admin:password@10.128.46.102"}               }
#
#swobject =  Get_switch_information.new(serverinfo,switchinfo)
#switchinfodetail = swobject.get_info
###pp switchinfodetail
