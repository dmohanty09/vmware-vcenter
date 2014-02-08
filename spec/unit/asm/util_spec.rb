require 'asm/util'
require 'spec_helper'
require 'tempfile'
require 'json'
require 'asm'

describe ASM::Util do
  
  before do
    @tmpfile = Tempfile.new('AsmUtil_spec')
  end

  after do
    @tmpfile.unlink
  end

  describe 'when device config file is valid' do

    it 'should be able to parse single device config file' do
      certname = 'equallogic-172.17.15.10'
      text = <<END
[#{certname}]
  type equallogic
  url https://eqluser:eqlpw@172.17.15.10

END
      @tmpfile.write(text)
      @tmpfile.close

      conf = ASM::Util.parse_device_config_file(@tmpfile)
      conf.keys.size.should eq 1
      conf[certname].provider.should eq 'equallogic'
      conf[certname].url.should eq 'https://eqluser:eqlpw@172.17.15.10'
    end

  end

  describe 'retries and timeouts' do

    it 'should reraise unhandled exceptions' do
      expect do
        ASM::Util.block_and_retry_until_ready(1) do
          raise(Exception)
        end
      end.to raise_error(Exception)
    end

    it 'should raise an exception on timeout' do
      expect do
        ASM::Util.block_and_retry_until_ready(1) do
          sleep 2
        end
      end.to raise_error(Timeout::Error)
    end

    it 'should forgive a single exception' do
      mock_log = mock('foo')
      mock_log.expects(:info).with('Caught exception Exception: Exception')
      self.expects(:foo).twice.raises(Exception).then.returns('bar')
      ASM::Util.block_and_retry_until_ready(5, Exception, nil, mock_log) do
        foo
      end.should == 'bar'
    end

    it 'should defer to max sleep time' do
      self.expects(:foo).twice.raises(Exception).then.returns('bar')
      ASM::Util.expects(:sleep).with(0.01)
      ASM::Util.block_and_retry_until_ready(5, Exception, 0.01) do
        foo
      end.should == 'bar'
    end

  end



  # TODO: test invalid device config files

  # TODO: test idrac resource configuration

  describe 'when data is valid' do
    it 'should produce component configuration data' do
      sample_file = File.join(File.dirname(__FILE__), '..', '..', 
                              'fixtures', 'dellworld_template.json')
      deployment = JSON.parse(File.open(sample_file, 'rb').read)['Deployment']['serviceTemplate']

      # Check a server component
      component = deployment['components'][1]
      title = component['id']

      config = {}
      resources = ASM::Util.asm_json_array(component['resources'])
      resources.each do |resource|
        config = ASM::Util.append_resource_configuration!(resource, config, title, nil)
      end
      
      config.keys.size.should == 2
      config['asm::idrac'].size.should == 1
      title = config['asm::idrac'].keys[0]
      config['asm::idrac'][title]['target_boot_device'].should == 'SD'
      config['asm::server'].size.should == 1
      title = config['asm::server'].keys[0]
      config['asm::server'][title]['razor_image'].should == 'esxi-5.1'
      
      
      # Check a cluster component
      component = deployment['components'][3]
      resources = ASM::Util.asm_json_array(component['resources'])
      title = component['id']
      resources.each do |resource|
        config = ASM::Util.append_resource_configuration!(resource, {}, title, nil)
      end
      
      config.keys.size.should == 1
      title = config['asm::cluster'].keys[0]
      config['asm::cluster'][title]['cluster'].should == 'dwcluster'
    end
  end

  describe 'when uuid is valid' do
    it 'should create the corresponding serial number' do
      uuid = '423b69b2-8bd7-0dde-746b-75c98eb74d2b'
      ASM::Util.vm_uuid_to_serial_number(uuid).should == 'VMware-42 3b 69 b2 8b d7 0d de-74 6b 75 c9 8e b7 4d 2b'
    end
  end
  
  describe 'when uuid is not valid' do
    it 'should raise an exception' do
      uuid = 'lkasdjflkasdj'
      expect do
        ASM::Util.vm_uuid_to_serial_number(uuid)
      end.to raise_error(Exception)
    end
  end

  it 'should parse esxcli output' do
    stdout = <<-eos
Name                    Virtual Switch  Active Clients  VLAN ID
----------------------  --------------  --------------  -------
ISCSI0                  vSwitch3                     1       16
ISCSI1                  vSwitch3                     1       16
Management Network      vSwitch0                     1        0
Management Network (1)  vSwitch0                     1       28
VM Network              vSwitch0                     1        0
Workload Network        vSwitch2                     0       20
vMotion                 vSwitch1                     1       23

    eos
    result = {
      'exit_status' => 0,
      'stdout' => stdout,
    }
    ASM::Util.stubs(:run_command_with_args).returns(result)
    endpoint = {}
    ret = ASM::Util.esxcli([], endpoint)
    ret.size.should == 7
    ret[3]['Name'].should == 'Management Network (1)'
    ret[3]['Virtual Switch'].should == 'vSwitch0'
    ret[3]['Active Clients'].should == '1'
    ret[3]['VLAN ID'].should == '28'
  end
  
end
