require 'spec_helper'
require 'asm/puppet_cert_manager'

describe ASM::PuppetCertManager do

  before do
    @id = '123'
     ASM::PuppetCertManager.stubs(:deployment_json_file).with(@id).returns(
      File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'find_cert_test.json')
    )
  end

  it 'should be able to find certs' do
    certs = ASM::PuppetCertManager.get_deployment_certs(@id)
    certs.should == ["agent-winbaremetal", "agent-gs1vmwin1", "agent-gs1vmwin2", "agent-gs1vmlin1", "agent-gs1vmlin2"]
  end

  it 'should be able to clean certs' do

    ASM::Util.expects(:run_command_simple)\
      .with('sudo puppet cert clean agent-winbaremetal agent-gs1vmwin1 agent-gs1vmwin2 agent-gs1vmlin1 agent-gs1vmlin2')\
        .returns({'exit_status' => 0})
    ASM::PuppetCertManager.clean_deployment_certs(@id)
  end

  it 'should raise an exception when cert clean fails' do
    ASM::Util.expects(:run_command_simple)\
      .with('sudo puppet cert clean agent-winbaremetal agent-gs1vmwin1 agent-gs1vmwin2 agent-gs1vmlin1 agent-gs1vmlin2')\
        .returns({'exit_status' => 1, 'stderr' => 'err', 'stdout' => 'out'})
    expect do
      ASM::PuppetCertManager.clean_deployment_certs(@id)
    end.to raise_error(Exception, /Call to puppet cert clean failed/)
  end

end
