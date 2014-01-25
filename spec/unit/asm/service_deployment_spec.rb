require 'asm/service_deployment'
require 'json'
require 'spec_helper'
require 'yaml'
require 'asm/util'

describe ASM::ServiceDeployment do

  before do
    @tmp_dir = Dir.mktmpdir
    @sd = ASM::ServiceDeployment.new('8000')
    @sd.stubs(:find_node).returns({})
    @sd.stubs(:create_broker_if_needed).returns("STUB-BROKER-NAME")
    @sd.stubs(:get_all_switches).returns([])
    @sd.stubs(:get_server_inventory).returns({})
    ASM.stubs(:base_dir).returns(@tmp_dir)
  end

  describe 'when data is valid' do

    before do
      @r_file = "#{@tmp_dir}/8000/resources/cert.yaml"
      @o_file = "#{@tmp_dir}/8000/cert.out"
      @data = {'serviceTemplate' => {'components' => [
        {'id' => 'cert', 'resources' => []}
      ]}}
    end

    it 'should be able to process data for a single resource' do
      ASM::Util.expects(:run_command).with(
        "sudo -i puppet asm process_node --filename #{@r_file} --run_type apply --always-override cert", "#{@o_file}") do |cmd|
        File.open(@o_file, 'w') do |fh|
          fh.write('Results: For 0 resources. 0 from our run failed. 0 not from our run failed. 0 updated successfully.')
        end
      end
      @data['serviceTemplate']['components'][0]['type'] = 'TEST'
      @data['serviceTemplate']['components'][0]['resources'].push(
        {'id' => 'user', 'parameters' => [
          {'id' => 'title', 'value' => 'foo'},
          {'id' => 'foo', 'value' => 'bar'}
        ]}
      )
      @sd.process(@data)
      YAML.load_file(@r_file)['user']['foo']['foo'].should == 'bar'
    end

    describe 'for server bare metal provisioining' do
      before do
        ASM.init
      end
      after do
        ASM.clear_mutex
      end
      it 'should fail is rule_number was already set' do
        @data['serviceTemplate']['components'][0]['type'] = 'SERVER'
        @data['serviceTemplate']['components'][0]['resources'].push(
          {'id' => 'asm::server', 'parameters' => [
            {'id' => 'title', 'value' => 'foo'},
            {'id' => 'rule_number', 'value' => 1},
          ]}
        )
        expect do
          @sd.process(@data)
        end.to raise_error(Exception, 'Did not expect rule_number in asm::server')
      end
      it 'should configure a server' do
        ASM::Util.expects(:run_command).with(
          "sudo -i puppet asm process_node --filename #{@r_file} --run_type apply --always-override cert", "#{@o_file}") do |cmd|
          File.open(@o_file, 'w') do |fh|
            fh.write('Results: For 0 resources. 0 from our run failed. 0 not from our run failed. 0 updated successfully.')
          end
        end
        @data['serviceTemplate']['components'][0]['type'] = 'SERVER'
        @data['serviceTemplate']['components'][0]['resources'].push(
          {'id' => 'asm::server', 'parameters' => [
            {'id' => 'title', 'value' => 'foo'},
            {'id' => 'admin_password', 'value' => 'foo'},
            {'id' => 'os_host_name', 'value' => 'foo'},
            {'id' => 'os_image_type', 'value' => 'foo'}
          ]}
        )
        @sd.process(@data)
        (YAML.load_file(@r_file)['asm::server']['foo']['rule_number'].to_s =~ /\d+/).should == 0
      end
      
      it 'should skip processing if server already deployed' do
        @sd.expects(:process_generic).never
        node = {'policy' => { 'name' => 'policy_test' } }
        @sd.stubs(:find_node).returns(node)
        policy = { 
          'repo' => {'name' => 'esxi-5.1'},
          'installer' => {'name' => 'vmware_esxi'} 
        }
        @sd.stubs(:get).returns(policy)
        @data['serviceTemplate']['components'][0]['id'] = 'bladeserver_serialno'
        @data['serviceTemplate']['components'][0]['type'] = 'SERVER'
        parameters = [ {'id' => 'title', 'value' => 'bladeserver_serialno'},
                       {'id' => 'razor_image', 'value' => 'esxi-5.1'},
                       {'id' => 'os_image_type', 'value' => 'vmware_esxi'}, ]
        resource = { 'id' => 'asm::server', 'parameters' => parameters }
        @data['serviceTemplate']['components'][0]['resources'].push(resource)
        @sd.process(@data)
      end
      
    end

  end

  describe 'when data is invalid' do

    it 'should warn when no serviceTemplate is defined' do
      @mock_log = mock('foo')
      @sd.expects(:logger).at_least_once.returns(@mock_log)
      @mock_log.expects(:debug).with('Found 0 components')
      @mock_log.expects(:info).with('Status: Started')
      @mock_log.expects(:info).with('Starting deployment ')
      @mock_log.expects(:warn).with('Service deployment data has no serviceTemplate defined')
      @mock_log.expects(:info).with('Status: Completed')
      @mock_log.expects(:debug).with('Switches configured in the environment []')
      @sd.process({})
    end

    it 'should warn when there are no components' do
      @mock_log = mock('foo')
      @sd.expects(:logger).at_least_once.returns(@mock_log)
      @mock_log.expects(:debug).with('Found 0 components')
      @mock_log.expects(:info).with('Status: Started')
      @mock_log.expects(:info).with('Starting deployment ')
      @mock_log.expects(:warn).with('service deployment data has no components')
      @mock_log.expects(:info).with('Status: Completed')
      @mock_log.expects(:debug).with('Switches configured in the environment []')
      @sd.process({'serviceTemplate' => {}})
    end

    it 'should fail when resources do not have types' do
      expect do
        @sd.process({'serviceTemplate' => {'components' => [
          {'id' => 'cert', 'type' => 'TEST', 'resources' => [
            {}
          ]}
        ]}})
      end.to raise_error(Exception, 'resource found with no type')
    end

    it 'should fail when resources do not have paremeters' do
      expect do
        @sd.process({'serviceTemplate' => {'components' => [
          {'type' => 'TEST', 'id' => 'cert2', 'resources' => [
            {'id' => 'user'}
          ]}
        ]}})
      end.to raise_error(Exception, 'resource of type user has no parameters')
    end

    it 'should fail when component has no certname' do
      expect do
        @sd.process({'serviceTemplate' => {'components' => [
          {'type' => 'TEST', 'resources' => [
            {'id' => 'user'}
          ]}
        ]}})
      end.to raise_error(Exception, 'Component has no certname')
    end

    it 'should fail when a resource has no title' do
      expect do
        @sd.process({'serviceTemplate' => {'components' => [
          {'type' => 'TEST', 'id' => 'foo', 'id' => 'cert4', 'resources' => [
            {'id' => 'user', 'parameters' => []}
          ]}
        ]}})
      end.to raise_error(Exception, 'Component has resource user with no title')
    end

  end

end
