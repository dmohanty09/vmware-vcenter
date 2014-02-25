require 'rexml/document'
require 'pathname'
require 'uri'
#require '/etc/puppetlabs/puppet/modules/asm_lib/lib/security/encode'

include REXML

class Reboot
  def initialize (ip,username,password)
    @ip = ip
    @username = username
    @password = password
    @password = URI.decode(get_plain_password(@password))
    module_path = Pathname.new(__FILE__).parent
    @rebootfilepath = "#{module_path}/rebootfilepath.xml"
  end

  def check_base64(string_input)
    if string_input =~ /^([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)$/
      true
    else
      false
    end
  end

  def get_plain_password(encoded_password)
    # Check if the password is encoded or not, if not then try to decrypt it
    if check_base64(encoded_password)
      plain_password=`/opt/puppet/bin/ruby /opt/asm-deployer/lib/asm/encode_asm.rb #{encoded_password}`
      plain_password=plain_password.strip
    else
      plain_password=encoded_password
    end
    return plain_password
  end

    
  def reboot(logger)
    # Create the reboot job
    logger.debug "Rebooting server #{@ip}"
    response = `wsman invoke -a CreateRebootJob http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_SoftwareInstallationService?CreationClassName=DCIM_SoftwareInstallationService,SystemCreationClassName=DCIM_ComputerSystem,SystemName=IDRAC:ID,Name=SoftwareUpdate -h "#{@ip}" -V -v -c dummy.cert -P 443 -u "#{@username}" -p "#{@password}" -J reboot.xml -j utf-8 -y basic -k "RebootJobType=2"`
    logger.debug "response :: #{response}"
    xmldoc = Document.new(response)
    instancenode = XPath.first(xmldoc, '//wsman:Selector Name="InstanceID"')
    tempinstancenode = instancenode
    if tempinstancenode.to_s == ""
      raise "Job ID not created"
    end
    instanceid=instancenode.text
    # Execute job
    response = `wsman invoke -a SetupJobQueue http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/dcim/DCIM_JobService?CreationClassName=DCIM_JobService,Name=JobService,SystemName=Idrac,SystemCreationClassName=DCIM_ComputerSystem -h "#{@ip}" -V -v -c dummy.cert -P 443 -u "#{@username}" -p "#{@password}" -j utf-8 -y basic -k "JobArray=#{instanceid}" -k "StartTimeInterval=TIME_NOW"`
    logger.debug "response :: #{response}"
    # get instance id
    xmldoc = Document.new(response)
    jobmessagenode = XPath.first(xmldoc, '//n1:Message')
    if tempinstancenode.to_s == ""
      raise "Job ID not created"
    end
    jobmessage=jobmessagenode.text
    logger.debug "Job Message #{jobmessage}"
    return true
  end
  
  def get_powerstate(logger)
    # Create the reboot job
    logger.debug "Getting the power state of the server with iDRAC IP: #{@ip}"
    response=`wsman enumerate http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/DCIM_CSAssociatedPowerManagementService -h "#{@ip}" -V -v -c dummy.cert -P 443 -u "#{@username}" -p "#{@password}" -j utf-8 -y basic`
    updated_xml=getxmls(response)
    xmldoc = Document.new(updated_xml[1][0])
    powerstate_node = XPath.first(xmldoc, '//n1:PowerState')
    powerstate=powerstate_node.text
    logger.debug "Power State: #{powerstate}"
    return powerstate
  end
  
  def getxmls(text)
    match_array=text.scan(/(<\?xml.*?<\/s:Envelope>?)/m)
    return match_array
  end
  
end

