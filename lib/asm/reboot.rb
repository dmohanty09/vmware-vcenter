require 'rexml/document'
require 'pathname'

include REXML

class Reboot
  def initialize (ip,username,password)
    @ip = ip
    @username = username
    @password = password
    module_path = Pathname.new(__FILE__).parent
    @rebootfilepath = "#{module_path}/rebootfilepath.xml"
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
end
