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

  def get_info(ser_info,sw_info,logger,server_nic_type=nil,server_vlan_info=nil)
    switchinfolist = []
    switchinfohash = {}
    ser_info.each do |nodename,sinfo|
      sinfo.each do |key,value|
        if key == 'bladetype'
          bladetype = value
          if bladetype == "rack"
            switchinfohash = rack_server_switch_info(nodename,sinfo,sw_info,logger,server_nic_type,server_vlan_info)
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

  def rack_server_switch_info(nname,sinfo,switchinfo,logger,server_nic_type,server_vlan_info)
    rackObj=Rack_server_switch_information.new(nname,sinfo,switchinfo)
    serverinformation=rackObj.identify_switch_ports(logger)
    
    configured_interfaces = get_configured_interfaces(server_nic_type,server_vlan_info,sinfo['mac_addresses'],logger)
    servermacaddress=rackObj.search_server_Macaddress(logger,configured_interfaces)
    
    logger.debug("Server MAC Address: #{servermacaddress}")
    
    # Check if all the
    server_mac_address_count = servermacaddress.count
    if configured_interfaces.count != server_mac_address_count
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
      servermacaddress=rackObj.search_server_Macaddress(logger,configured_interfaces)
      server_mac_address_count=sinfo["mac_addresses"].length()
      if configured_interfaces.count != server_mac_address_count
        logger.debug "#{nname}:Not able to identify the server information for all interfaces, seems it is not connected"
      end
    end

    return servermacaddress
  end
  
  def get_configured_interfaces(server_nic_type,server_vlan_info,macArray,logger)
    # Using server vlan info, get fabrics where vlans needs to be configured
    fabrics = []
    configured_interfaces = []
    ('A'..'Z').each do |fabric_prefix|
      fabric = "Fabric #{fabric_prefix}"
      if server_vlan_info[fabric]
        tagged_vlan = server_vlan_info["#{fabric}"]['tagged_vlan']
        untagged_vlan = server_vlan_info["#{fabric}"]['untagged_vlan']
          
        if (tagged_vlan.nil? or tagged_vlan.length == 0) and ( untagged_vlan.nil? or untagged_vlan.length == 0)
          logger.debug "Fabric #{fabric} do not have vlans"
        else
          logger.debug "Fabric #{fabric} needs to be configured"
          fabrics.push(fabric)
        end
      end
    end
    
    logger.debug "Fabrics that needs to be configured: #{fabrics}"
    interfaces = macArray.keys.sort
    slots = []
    slot_interface = {}
    integrated_slot = []
    additional_slot = []
    integrated_slot_interface = {}
    additional_slot_interface = {}
      
    interfaces.each do |interface|
      logger.debug("interface: #{interface}")
      interface_info = interface.match(/NIC.(Slot|Integrated).(\d+)-(\d+)-(\d+)/)
      integrated_slot.push("#{interface_info[2]}") if interface_info[1] == "Integrated"
      additional_slot.push("#{interface_info[2]}") if interface_info[1] == "Slot"
      
      #slots.push(interface_info[2])
      #slot_interface["#{interface_info[2]}"] = interface_info[1]
      integrated_slot_interface["#{interface_info[2]}"] = interface_info[1] if interface_info[1] == "Integrated"
      additional_slot_interface["#{interface_info[2]}"] = interface_info[1] if interface_info[1] == "Slot"
    end
    #slots = slots.uniq.sort
    integrated_slot = integrated_slot.uniq.sort
    additional_slot = additional_slot.uniq.sort
    
    # Integrated NICS first and then then additional slot
    logger.debug("Integrated slots where MAC address is retrieved :#{integrated_slot}")
    logger.debug("Additional slots where MAC address is retrieved :#{additional_slot}")
    
    slots = integrated_slot.concat(additional_slot).first(fabrics.length)
    
    fabrics.each_with_index do |fabric,index|
      slot_name = slots[index]
      nic_count = server_nic_type["#{fabric}"]
      suffix = "Slot"
      (1..nic_count).each do |count|
        if !integrated_slot_interface["#{slot_name}"].nil?
          suffix = "Integrated"
          integrated_slot_interface.delete("#{slot_name}")
        end
        int_name = "NIC.#{suffix}.#{slot_name}-#{count}-1"
        configured_interfaces.push(int_name)
      end
    end
    logger.debug "Configured Interfaces: #{configured_interfaces}"
    configured_interfaces
  end
  
  def get_fabic_configured_interfaces(server_nic_type,server_vlan_info,macArray,logger)
    # Using server vlan info, get fabrics where vlans needs to be configured
    fabrics = []
    configured_interfaces = []
    ('A'..'Z').each do |fabric_sufix|
      fabric = "Fabric #{fabric_sufix}"
      if server_vlan_info[fabric]
        tagged_vlan = server_vlan_info["#{fabric}"]['tagged_vlan']
        untagged_vlan = server_vlan_info["#{fabric}"]['untagged_vlan']

        if (tagged_vlan.nil? or tagged_vlan.length == 0) and ( untagged_vlan.nil? or untagged_vlan.length == 0)
          logger.debug "Fabric #{fabric} do not have vlans"
        else
          logger.debug "Fabric #{fabric} needs to be configured"
          fabrics.push(fabric)
        end
      end
    end

    logger.debug "Fabrics that needs to be configured: #{fabrics}"
    interfaces = macArray.keys.sort
    slots = []
    intergrated_slots = []
    additional_slots = []
    integrated_slot_interface = {}
    additional_slot_interface = {}
    integrated_slot_interfaces = {}
    additional_slot_interfaces = {}
      
    interfaces.each do |interface|
      interface_info = interface.match(/NIC.(Slot|Integrated).(\d+)-(\d+)-(\d+)/)
      intergrated_slots.push(interface_info[2]) if interface_info[1] == "Integrated"
      additional_slots.push(interface_info[2]) if interface_info[1] == "Slot"
      
      integrated_slot_interface["#{interface_info[2]}"] = interface_info[1] if interface_info[1] == "Integrated"
      additional_slot_interface["#{interface_info[2]}"] = interface_info[1] if interface_info[1] == "Slot"  
        
      integrated_slot_interfaces["#{interface_info[2]}"] ||= []
      additional_slot_interfaces["#{interface_info[2]}"] ||= []
        
      integrated_slot_interfaces["#{interface_info[2]}"].push(macArray[interface]) if interface_info[1] == "Integrated"
      additional_slot_interfaces["#{interface_info[2]}"].push(macArray[interface]) if interface_info[1] == "Slot"
    end
    
    intergrated_slots = intergrated_slots.uniq.sort
    additional_slots = additional_slots.uniq.sort
    slots = intergrated_slots.concat(additional_slots).first(fabrics.length)

    logger.debug("Integrated slot interfaces :#{integrated_slot_interfaces}")
    logger.debug("Additional slot interfaces :#{additional_slot_interfaces}")

    interface_info = {}
    fabrics.each_with_index do |fabric,index|
      slot_name = slots[index]
      if integrated_slot_interfaces[slot_name]
        interface_info[fabric] = integrated_slot_interfaces[slot_name]
        integrated_slot_interfaces.delete(slot_name)
      else
        interface_info[fabric] = additional_slot_interfaces[slot_name]
      end
    end
    logger.debug("Interface info : #{interface_info}")
    interface_info
  end
  

end
