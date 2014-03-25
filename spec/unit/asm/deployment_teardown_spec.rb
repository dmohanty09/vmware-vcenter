require 'spec_helper'
require 'asm/deployment_teardown'
require 'asm'

describe ASM::DeploymentTeardown do

  before do
    ASM.init
    @id = '123'
    @names = ["agent-winbaremetal", "agent-gs1vmwin1", "agent-gs1vmwin2", "agent-gs1vmlin1", "agent-gs1vmlin2"]
     ASM::DeploymentTeardown.stubs(:deployment_json_file).with(@id).returns(
      File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'deployment_teardown_test.json')
    )
    file = File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'deployment_teardown_test.json')
    dt = JSON.parse(File.read(file))
    @data = dt['Deployment'] || {}
  end

  after do
    ASM.clear_mutex
  end

  it 'should be able to find certs' do
    certs = ASM::DeploymentTeardown.get_deployment_certs(@data)
    certs.should == ["agent-winbaremetal", "agent-gs1vmwin1", "agent-gs1vmwin2", "agent-gs1vmlin1", "agent-gs1vmlin2"]
  end

  it 'should be able to clean certs' do

    ASM::Util.expects(:run_command_simple)\
      .with('sudo puppet cert clean agent-winbaremetal agent-gs1vmwin1 agent-gs1vmwin2 agent-gs1vmlin1 agent-gs1vmlin2')\
        .returns({'exit_status' => 0})
    ASM::DeploymentTeardown.clean_deployment_certs(@names)
  end

  it 'should raise an exception when cert clean fails' do
    ASM::Util.expects(:run_command_simple)\
      .with('sudo puppet cert clean agent-winbaremetal agent-gs1vmwin1 agent-gs1vmwin2 agent-gs1vmlin1 agent-gs1vmlin2')\
        .returns({'exit_status' => 1, 'stderr' => 'err', 'stdout' => 'out'})
    expect do
      ASM::DeploymentTeardown.clean_deployment_certs(@names)
    end.to raise_error(Exception, /Call to puppet cert clean failed/)
  end


  it 'should be able to deactivate nodes' do 
    ASM::Util.expects(:run_command_simple)\
      .with('sudo puppet node deactivate agent-winbaremetal agent-gs1vmwin1 agent-gs1vmwin2 agent-gs1vmlin1 agent-gs1vmlin2')\
        .returns({'exit_status' => 0})
    ASM::DeploymentTeardown.clean_puppetdb_nodes(@names)
  end

  #Puppet deactivate will always send a request to puppetdb to deactivate node, so no real error can be tested

  it 'should be able to return a list of puppet nodes/certs deactivated/cleared' do
    name_string = "agent-winbaremetal agent-gs1vmwin1 agent-gs1vmwin2 agent-gs1vmlin1 agent-gs1vmlin2"

    ASM::DeploymentTeardown.expects(:get_deployment_certs)\
      .with(@data)\
        .returns(@names)
    ASM::DeploymentTeardown.expects(:clean_puppetdb_nodes)
      .with(@names)
        .returns(name_string)
    ASM::DeploymentTeardown.expects(:clean_deployment_certs)
      .with(@names)
        .returns(name_string)

    ASM::DeploymentTeardown.clean_deployment(@id)
  end

  it 'should return just host names from puppet cert list all' do
    result =  {"stdout"=>"+ \"dell_ftos-172.17.15.234\" (SHA256) 1C:DB:87:DA:4B:BF:92:A6:0F:71:F1:EE:BC:0B:31:75:0D:BF:58:14:CE:3B:A2:34:E7:72:BF:7E:AB:BD:07:9A\n+ \"dell_ftos-172.17.15.237\" (SHA256) A5:C1:95:ED:48:AF:65:F6:A3:D7:85:B8:6B:E7:C0:20:29:02:97:6D:CB:F3:A3:67:92:CC:E7:68:E7:96:EC:94\n+ \"dellasm\"                 (SHA256) 16:C0:9F:0B:04:22:58:74:BC:3F:DB:F8:DC:8B:D7:E5:2C:2E:1D:52:BA:69:BF:AF:93:95:FE:71:D9:5F:E5:1F (alt names: \"DNS:dellasm\", \"DNS:dellasm.aus.amer.dell.com\", \"DNS:puppet\")\n+ \"equallogic-172.17.15.10\" (SHA256) 21:2A:62:83:51:93:FB:A7:6F:97:30:C0:3C:97:7F:81:6E:65:36:C8:51:AA:6A:93:2E:BA:6A:AC:D2:C5:0D:E1\n", "stderr"=>"", "pid"=>3170, "exit_status"=>0}
    ASM::Util.stubs(:run_command_simple).returns(result)
    ASM::DeploymentTeardown.get_deployed_certs().should == ["dell_ftos-172.17.15.234", "dell_ftos-172.17.15.237", "dellasm", "equallogic-172.17.15.10"]
  end

end
