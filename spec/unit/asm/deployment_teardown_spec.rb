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

end
