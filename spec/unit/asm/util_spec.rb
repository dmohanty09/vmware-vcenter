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
        config = ASM::Util.append_resource_configuration!(resource, config, :title => title)
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
        config = ASM::Util.append_resource_configuration!(resource, {}, :title => title)
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

  describe 'when hash is deep' do
    it 'should sanitize password value' do
      raw = {'foo' => {'password' => 'secret'}}
      ASM::Util.sanitize(raw).should == {'foo' => {'password' => '******'}}
    end

    it 'should maintain password value' do
      raw = {'foo' => {'password' => 'secret'}}
      ASM::Util.sanitize(raw)
      raw.should == {'foo' => {'password' => 'secret'}} 
    end
  end

  describe 'when hosts already deployed' do
    it 'should return hosts if they are already deployed' do
      ASM.stubs(:block_hostlist).returns([])
      ASM::Util.stubs(:get_puppet_certs).returns(['server1','server2'])
      ASM::Util.check_host_list_against_previous_deployments(['server1','server2', 'server3']).should == ['server1','server2']
      ASM::Util.unstub(:get_puppet_certs)
    end
  end

  it 'should return just host names from puppet cert list all' do
    result =  Hashie::Mash.new({"stdout"=>"+ \"dell_ftos-172.17.15.234\" (SHA256) 1C:DB:87:DA:4B:BF:92:A6:0F:71:F1:EE:BC:0B:31:75:0D:BF:58:14:CE:3B:A2:34:E7:72:BF:7E:AB:BD:07:9A\n+ \"dell_ftos-172.17.15.237\" (SHA256) A5:C1:95:ED:48:AF:65:F6:A3:D7:85:B8:6B:E7:C0:20:29:02:97:6D:CB:F3:A3:67:92:CC:E7:68:E7:96:EC:94\n+ \"dellasm\"                 (SHA256) 16:C0:9F:0B:04:22:58:74:BC:3F:DB:F8:DC:8B:D7:E5:2C:2E:1D:52:BA:69:BF:AF:93:95:FE:71:D9:5F:E5:1F (alt names: \"DNS:dellasm\", \"DNS:dellasm.aus.amer.dell.com\", \"DNS:puppet\")\n+ \"equallogic-172.17.15.10\" (SHA256) 21:2A:62:83:51:93:FB:A7:6F:97:30:C0:3C:97:7F:81:6E:65:36:C8:51:AA:6A:93:2E:BA:6A:AC:D2:C5:0D:E1\n", "stderr"=>"", "pid"=>3170, "exit_status"=>0})
    ASM::Util.stubs(:run_command_success).returns(result)
    ASM::Util.get_puppet_certs.should == ["dell_ftos-172.17.15.234", "dell_ftos-172.17.15.237", "dellasm", "equallogic-172.17.15.10"]
  end

end
