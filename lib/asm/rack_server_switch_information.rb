#require 'yaml'
#require 'json'
require 'crack'

class Rack_server_switch_information
  def initialize(servicetag,sinfo,swinfo)
    @serverinfo=sinfo
    @switchinfo=swinfo
    @ServiceTag=servicetag
    @mainremotehash={}
    @mainportchhash={}

    @matchedHash={}

  end

  def identify_switch_ports(logger)
    logger.debug "******** #{@switchinfo} *************"
    @switchinfo.keys.each do |certname|
      logger.debug "certname :: #{certname}"
      output = `sudo puppet facts find #{certname} --terminus yaml --clientyamldir=/var/opt/lib/pe-puppet/yaml/ --color=false`
      logger.debug "************ output :: #{output} ******************"
      if output.empty? || ( !output.match("remotedeviceinfo") && !output.match("remote_device_info") )
        next
      end
      hash = Crack::JSON.parse(output)
      valuesHash=hash["values"]
      remoteHash=valuesHash["remote_device_info"]
      if !remoteHash
        remoteHash=valuesHash["remotedeviceinfo"]
      end
      portChHash=valuesHash["port_channels"]
      if !portChHash
        portChHash=valuesHash["portchannelmap"]
      end
      newremotehash = Crack::JSON.parse(remoteHash)
      @mainremotehash.store(certname,newremotehash)
      newportchhash = Crack::JSON.parse(portChHash)
      @mainportchhash.store(certname,newportchhash)

    end
  end
end

def search_server_Macaddress_force10(certname,mac,logger)
  interface_found="false"

  cert_port=[]
  intfLoc1=[]
  ports=[]
  cert_ports=[]
  @mainremotehash[certname].keys.each do |intf|
    newremotehash1=@mainremotehash[certname]
    intfHash = newremotehash1[intf]
    remote_mac = intfHash["remote_mac"]
    if !remote_mac
      remote_mac = intfHash["mac_address"]
    end
    intfLoc=intf
    logger.debug "search_server_Macaddress_force10: intfLoc: #{intfLoc}  mac: #{mac} remote_mac: #{remote_mac.upcase} "
    if mac.include?(remote_mac.upcase)
      logger.debug "search_server_Macaddress_force10: Matched intfLoc: #{intfLoc}  macArray: #{mac} remote_mac: #{remote_mac.upcase} "
      lag=getLAGFromIntf(intf,certname)
      if !lag.empty?
        ports=intfLoc1.push(lag)
      else
        ports=intfLoc1.push(intfLoc)
      end
      interface_found="true"
    end
  end
  if interface_found == "true"
    cert_port.push(certname)
    cert_port.push(ports)
    cert_ports.push(cert_port)
    #logger.debug "search_server_Macaddress_force10: Adding in matchedhash remote_mac.: #{remote_mac} and  cert_port: #{cert_port} and cert_ports: #{@cert_ports} "
    @matchedHash.store(mac.upcase,cert_ports)
  end

end

def search_server_Macaddress_powerconnect(certname,mac,logger)
  interface_found="false"
  remote_mac=""
  cert_port=[]
    cert_ports=[]
  intfLoc1=[]
  ports=[]

  newremotehash1=@mainremotehash[certname]
  logger.debug " newremotehash1: #{newremotehash1} **************"
  newremotehash1.keys.each do |remote_mac|
    intfLoc=newremotehash1[remote_mac]
    remote_mac=remote_mac.gsub(/(\w{2})(\w{2})\.(\w{2})(\w{2})\.(\w{2})(\w{2})/,'\1:\2:\3:\4:\5:\6')
    logger.debug "search_server_Macaddress_powerconnect : intfLoc: #{intfLoc}  mac: #{mac} remote_mac: #{remote_mac.upcase} "
    if mac.include?(remote_mac.upcase)
      logger.debug "search_server_Macaddress_powerconnect : intfLoc: #{intfLoc}   remote_mac: #{remote_mac.upcase} "
      ports=intfLoc1.push(intfLoc)
      interface_found="true"
    end

  end
  #end
  if interface_found == "true"
    cert_port.push(certname)
    cert_port.push(ports)
    cert_ports.push(cert_port)
    #logger.debug "search_server_Macaddress_powerconnect: Adding in matchedhash remote_mac.: #{remote_mac} and  cert_port: #{cert_port} and @cert_ports: #{@cert_ports} "
    @matchedHash.store(mac.upcase,cert_ports)
  end

end

public

def search_server_Macaddress(logger,configured_interfaces)
  serviceTag=@ServiceTag
  dataHash= @serverinfo
  macArray= dataHash["mac_addresses"]
  logger.debug "Mac Array: #{macArray.inspect}"
  logger.debug("Interfaces that needs to be configured: #{configured_interfaces}")
  
  configured_interfaces.each do |interface|
    logger.debug("Interface for which MAC address needs to be searched : #{interface}")
    mac = macArray["#{interface}"]
    logger.debug("mac address : #{mac}")
    @interface_found="false"
    @cert_ports=[]
    @mainremotehash.keys.each do |certname|
      logger.debug("Searching for switch #{certname}")
      match = certname.match(/powerconnect/)
      if match
        search_server_Macaddress_powerconnect(certname,mac,logger)
      else
        search_server_Macaddress_force10(certname,mac,logger)
      end
    end
  end
  return @matchedHash
end

private

def getLAGFromIntf(intf,certname)
  ports=[]
  @mainportchhash[certname].keys.each do |lag|
    newportchhash2= @mainportchhash[certname]
    ports=[]
    lagHash =  newportchhash2[lag]
    port = lagHash["ports"]
    if port
      port.split(",").each do |p|
        p.match(/(.*)\(/)
        ports.push($1.strip)
      end
    else
      lagHash.split(",").each do |p|
        ports.push(p.strip)
      end
    end
    if ports.include?(intf)
      return lag
    end
  end
  return ""
end

