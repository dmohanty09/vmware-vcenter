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
      ASM.expects(:logger).returns(mock_log)
      mock_log.expects(:info).with('Caught exception Exception: Exception')
      self.expects(:foo).twice.raises(Exception).then.returns('bar')
      ASM::Util.block_and_retry_until_ready(5, Exception) do
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
        config = ASM::Util.append_resource_configuration!(resource, config, title)
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
        config = ASM::Util.append_resource_configuration!(resource, {}, title)
      end
      
      config.keys.size.should == 1
      title = config['asm::cluster'].keys[0]
      config['asm::cluster'][title]['cluster'].should == 'dwcluster'
    end
  end

  
end
