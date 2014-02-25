#require 'yaml'
#require 'json'
require 'crack'
require 'asm/discoverswitch'

class San_switch_information
  def initialize(servicetag,sinfo,swinfo)
    @serverinfo=sinfo
    @switchinfo=swinfo
    @ServiceTag=servicetag
    @mainremotehash={}
    @mainportchhash={}

    @matchedHash={}

  end

  def identify_switch_ports(compellent_contollers,logger)
    logger.debug "******** #{@switchinfo} *************"
    @switchinfo.keys.each do |certname|
      logger.debug "certname :: #{certname}"
      output = `sudo puppet facts find #{certname} --terminus yaml --clientyamldir=/var/opt/lib/pe-puppet/yaml/ --color=false`
      logger.debug "************ output :: #{output} ******************"
      if output.empty? || ( !output.match("RemoteDeviceInfo")  )
        next
      end
      hash = Crack::JSON.parse(output)
      valuesHash=hash["values"]
      remoteHash=valuesHash["RemoteDeviceInfo "]
      active_zoneset=nil
      active_zoneset||=valuesHash["Effective Cfg"]
      nameserver_data=valuesHash["Nameserver"]
      nameserver_hash=Crack::JSON.parse(nameserver_data)
      fault_domain_name=get_fault_domain(nameserver_hash,compellent_contollers,logger)
      logger.debug("Fault domain name comming from discovery data: #{fault_domain_name}")
            
      #logger.debug"Remote hash: #{remoteHash}"
      newremotehash = Crack::JSON.parse(remoteHash)
      switchinfo = {'remote_hash' => newremotehash,
        'effective_cfg' => active_zoneset,
        'fault_domain_name' => fault_domain_name
      }
      @mainremotehash.store(certname,switchinfo)
    end
  end
  #end

  def search_server_Macaddress_brocade(certname,mac,compellent_contollers,logger)
    interface_found="false"
    remote_mac=""
    cert_port=[]
    cert_ports=[]
    intfLoc1=[]
    ports=[]
    #logger.debug "Searching WWPN for brocade switch"

    newremotehash1=@mainremotehash[certname]['remote_hash']
    effective_zoneset=@mainremotehash[certname]['effective_cfg']
    fault_domain_name=@mainremotehash[certname]['fault_domain_name']
      logger.debug"Fault Domain Alias: #{fault_domain_name}"
    
    logger.debug " newremotehash1: #{newremotehash1.inspect} **************"
    newremotehash1.each do |intfLoc,portattr|
      #intfLoc=newremotehash1[remote_mac]
      #remote_mac=remote_mac.gsub(/(\w{2})(\w{2})\.(\w{2})(\w{2})\.(\w{2})(\w{2})/,'\1:\2:\3:\4:\5:\6')
      logger.debug"Port Attribute: #{portattr.inspect}"
      remote_wwpn = portattr['mac_address']
      logger.debug "Brocade Port Location : #{intfLoc}"
      logger.debug "Remote WWPN: #{remote_wwpn}"
      #logger.debug "search_server_Macaddress_brocade : intfLoc: #{intfLoc}  wwpn: #{mac} remote_wwpn: #{remote_wwpn.upcase} "
      if remote_wwpn.nil?
        next
      end
      if remote_wwpn.upcase.include?(mac)
        logger.debug "search_server_Macaddress_brocade : Match found : intfLoc: #{intfLoc}   remote_wwpn: #{remote_wwpn.upcase} "
        ports=intfLoc1.push(intfLoc)
        interface_found="true"
        break
      end

    end
    #end
    if interface_found == "true"
      cert_port.push(certname)
      cert_port.push(ports)
      cert_port.push(effective_zoneset)
      cert_port.push(fault_domain_name)
      cert_ports.push(cert_port)
      #logger.debug "search_server_Macaddress_powerconnect: Adding in matchedhash remote_mac.: #{remote_mac} and  cert_port: #{cert_port} and @cert_ports: #{@cert_ports} "
      @matchedHash.store(mac.upcase,cert_ports)
    end

  end

  def search_server_Macaddress(wwpns,compellent_contollers,logger)
    serviceTag=@ServiceTag
    #serviceTag=@ServiceTag
    dataHash= @serverinfo
    macArray= wwpns
    #@remote_mac=""
    logger.debug "Search for the Server WWPNs #{wwpns} in the device facts"

    macArray.each do |mac|
      logger.debug "WWPN from the server: #{mac}"
      if mac.nil?
        next
      end
      @interface_found="false"
      @cert_ports=[]
      @mainremotehash.keys.each do |certname|
        logger.debug "Switch cert name: #{certname}"
        if certname.match(/brocade/)
          search_server_Macaddress_brocade(certname,mac,compellent_contollers,logger)
        else
          logger.debug"SAN switch #{certname} is not suppported"
        end
      end
    end
    logger.debug "Matched hash: #{@matchedHash}"
    return @matchedHash
  end
  
  def get_fault_domain(nameserver_hash,compellent_contollers,logger)
    # TODO: Needs to add the check for the compellent controller name
    # The value of the controller list needs to be passed from the upper layer
    fault_domain_name=""
    nameserver_hash.each do |ns_id, ns_info|
      logger.debug "nameserver id: #{ns_id}"
      logger.debug "nameserver info: #{ns_info}"
      logger.debug "compellent_contollers #{compellent_contollers}"
      if (ns_info['port_info'].downcase.match(/compellent/) != nil) and
      (ns_info['device_type'] == 'NPIV Unknown(initiator/target)') and
        ((ns_info['port_info'].match(/#{compellent_contollers['controller1']}/) != nil) or
           (ns_info['port_info'].match(/#{compellent_contollers['controller2']}/ ) != nil))
        fault_domain_name=ns_info['device_alias']
          logger.debug "Found nsid entry : #{}"
          break
      end
    end
    fault_domain_name
  end

end
  

