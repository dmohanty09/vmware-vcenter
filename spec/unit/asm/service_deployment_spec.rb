require 'asm/service_deployment'
require 'json'
require 'spec_helper'
require 'yaml'
require 'asm/util'

describe ASM::ServiceDeployment do

  before do
    ENV['MOCK_SEQUEL'] = 'true'
    DB = Sequel.mock
    ASM.init
    @tmp_dir = Dir.mktmpdir
    @sd = ASM::ServiceDeployment.new('8000')
    @sd.stubs(:find_node).returns({})
    @sd.stubs(:create_broker_if_needed).returns('STUB-BROKER-NAME')
    @sd.stubs(:get_all_switches).returns([])
    @sd.stubs(:get_server_inventory).returns({})
    @sd.stubs(:update_inventory_through_controller)
    ASM.stubs(:base_dir).returns(@tmp_dir)
    network = {
      'id' => '1', 'name' => 'Test Network', 'vlanId' => '28', 
      'staticNetworkConfiguration' => {
        'gateway' => '172.28.0.1', 'subnet' => '255.255.0.0'
      }
    }
    ASM::Util.stubs(:fetch_network_settings).returns(network)
    ASM::Util.stubs(:reserve_network_ips).returns(['172.28.118.1'])
  end

  after do
    ASM.clear_mutex
  end

  describe 'when data is valid' do

    before do
      FileUtils.mkdir_p("#{@tmp_dir}/8000/resources")
      @r_file = "#{@tmp_dir}/8000/resources/cert.yaml"
      @o_file = "#{@tmp_dir}/8000/cert.out"
      @data = {'serviceTemplate' => {'components' => [
        {'id' => 'id', 'puppetCertName' => 'cert', 'resources' => []}
      ]}}
    end

    it 'should be able to process data for a single resource' do
      File.open( "#{@tmp_dir}/8000/cert.out", 'w') do |fh|
        fh.write('Results: For 0 resources. 0 from our run failed. 0 not from our run failed. 0 updated successfully.')
      end
      ASM::Util.expects(:run_command).with(
        "sudo puppet asm process_node --debug --trace --filename #{@r_file} --run_type apply --statedir #{@tmp_dir}/8000/resources  --always-override cert", "#{@o_file}")
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

        RestClient.stubs(:get)
        .with(URI.escape("http://localhost:7080/v3/nodes?query=[\"and\", [\"=\", [\"node\", \"active\"], true], [\"=\", \"name\", \"agent-foo\"]]]"),
        {:content_type => :json, :accept => :json})
        .returns('[{"name":"agent-foo"}]')

        RestClient.stubs(:get)
        .with(URI.escape("http://localhost:7080/v3/reports?query=[\"=\", \"certname\", \"agent-foo\"]&order-by=[{\"field\": \"receive-time\", \"order\": \"desc\"}]&limit=1"),
        {:content_type => :json, :accept => :json})
        .returns('[{"receive-time":"1969-01-01 01:00:00 -0600", "hash":"fooreport"}]')

        RestClient.stubs(:get)
        .with(URI.escape("http://localhost:7080/v3/events?query=[\"=\", \"report\", \"fooreport\"]"),
        {:content_type => :json, :accept => :json})
        .returns('[{"name":"agent-foo"}]')

        Time.stubs(:now).returns(Time.new("1969-01-01 00:00:00 -0600"))
        #1388534400 is time at Jan 1, 2014.  Used in the rule_number function.
        @sd.stubs(:rule_number).returns(1388534400)

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
          'task' => {'name' => 'vmware_esxi'} 
        }
        @sd.stubs(:get).returns(policy)
        @data['serviceTemplate']['components'][0]['id'] = 'bladeserver_serialno'
        @data['serviceTemplate']['components'][0]['puppetCertName'] = 'bladeserver_serialno'
        @data['serviceTemplate']['components'][0]['type'] = 'SERVER'
        parameters = [ {'id' => 'title', 'value' => 'bladeserver_serialno'},
                       {'id' => 'razor_image', 'value' => 'esxi-5.1'},
                       {'id' => 'os_image_type', 'value' => 'vmware_esxi'}, 
                       {'id' => 'os_host_name', 'value' => 'foo'}]
        resource = { 'id' => 'asm::server', 'parameters' => parameters }
        @data['serviceTemplate']['components'][0]['resources'].push(resource)
        @sd.process(@data)
      end

      describe 'hyperV server' do
        it 'should process hyperv servers' do
          component =  {'id' => 'id', 'resources' => []}
          node = {'policy' => { 'name' => 'policy_test' } }
          @sd.stubs(:find_node).returns(node)
          policy = { 
            'repo' => {'name' => 'esxi-5.1'},
            'installer' => {'name' => 'vmware_esxi'} 
          }
          @sd.stubs(:get).returns(policy)
          @sd.expects(:rule_number).returns(1)
          component['id'] = 'id'
          component['puppetCertName'] = 'bladeserver-serialno'
          component['type'] = 'SERVER'
          parameters = [ {'id' => 'title', 'value' => 'bladeserver-serialno'},
                         {'id' => 'os_image_type', 'value' => 'hyperv'},
                         {'id' => 'os_host_name', 'value' => 'foo'}
                       ]
          resource1 = { 'id' => 'asm::server', 'parameters' => parameters }
          @sd.debug = true
          component['resources'].push(resource1)

          component['relatedComponents'] = { 'entry'  => {
              'key'   => 'k1',
              'value' => 'v1'
          }}
          @sd.set_components_by_type('STORAGE',
          [
            {'id' => 'k1',
             'puppetCertName' => 'k1',
             'componentID'=>'s1',
             'resources' => [{
               'id' => 'equallogic::create_vol_chap_user_access',
               'parameters' => [
                 {'id' => 'title', 'value' => 'vol1'}
               ]
             }]
            },
            {'id' => 'k1',
             'puppetCertName' => 'k1',
             'componentID'=>'s1',
             'resources' => [{
               'id' => 'equallogic::create_vol_chap_user_access',
               'parameters' => [
                 {'id' => 'title', 'value' => 'vol2'}
               ]
             }]
            }
          ])
          ASM::Util.expects(:find_equallogic_iscsi_ip).with('k1').returns('127.0.1.1')
          ASM::Processor::Server.expects(:munge_hyperv_server).with(
            'bladeserver-serialno',
             {'asm::server' => {'bladeserver-serialno' => {'os_image_type' => 'hyperv', 'os_host_name' => 'foo', 'rule_number' => 1, 'broker_type' => 'puppet', 'serial_number' => 'SERIALNO', 'policy_name' => 'policy-foo-8000', 'cert_name' => 'agent-foo'}}},
            '127.0.1.1',
            ['vol1', 'vol2'],
            false,
            'iscsi'
          ).returns({})
          @sd.process_server(component)
          @sd.debug = false
        end

      end
      
    end

    it 'should replace network guids with networks' do
      network = {
        'id' => '1', 'name' => 'Test Network', 'vlanId' => '28', 
        'staticNetworkConfiguration' => {
          'gateway' => '172.28.0.1', 'subnet' => '255.255.0.0'
        }
      }
      ASM::Util.stubs(:fetch_network_settings).returns(network)
      ASM::Util.stubs(:reserve_network_ips).returns(['172.28.118.1'])
      
      param = { 'id' => 'hypervisor_network', 'value' => '1', }
      servers = [ {'id' => 'cert', 
                    'resources' => { 'parameters' => [ param ] } } ]
      @sd.massage_networks!(servers)
      updated = servers[0]['resources']['parameters'][0]
      updated['value'].size.should == 1
      updated['value'][0]['staticNetworkConfiguration']['ip_address'].should == '172.28.118.1'
    end
    
    it 'should reserve two networks for storage_network' do
      network = {
        'id' => '1', 'name' => 'Test Network', 'vlanId' => '28', 
        'staticNetworkConfiguration' => {
          'gateway' => '172.28.0.1', 'subnet' => '255.255.0.0'
        }
      }
      ASM::Util.stubs(:fetch_network_settings).returns(network)
      ASM::Util.stubs(:reserve_network_ips).returns(['172.28.118.1', '172.28.118.2'])
      
      param = { 'id' => 'storage_network', 'value' => '1', }
      servers = [ {'id' => 'cert', 'resources' => { 'parameters' => [ param ] } } ]
      @sd.massage_networks!(servers)

      updated = servers[0]['resources']['parameters'][0]
      updated['value'].size.should == 2
      updated['value'][0]['staticNetworkConfiguration']['ip_address'].should == '172.28.118.1'
      updated['value'][1]['staticNetworkConfiguration']['ip_address'].should == '172.28.118.2'
    end

    it 'should not reserve ips for dhcp networks' do
      network = {
        'id' => '1', 'name' => 'Test Network',
        'vlanId' => '28', "static" => 'false'
      }
      ASM::Util.stubs(:fetch_network_settings).returns(network)
      ASM::Util.expects(:reserve_network_ips).never
      
      param = { 'id' => 'workload_network', 'value' => '1', }
      servers = [ {'id' => 'cert', 'resources' => { 'parameters' => [ param ] } } ]
      @sd.massage_networks!(servers)

      updated = servers[0]['resources']['parameters'][0]
      updated['value'].size.should == 1
      updated['value'].should == [ network ]
    end

    it 'should disallow Management Network name' do
      network = {
        'id' => '1', 'name' => 'Management Network',
        'vlanId' => '28', "static" => 'false'
      }
      ASM::Util.stubs(:fetch_network_settings).returns(network)
      ASM::Util.expects(:reserve_network_ips).never
      
      param = { 'id' => 'workload_network', 'value' => '1', }
      servers = [ {'id' => 'cert', 'resources' => { 'parameters' => [ param ] } } ]
      @sd.massage_networks!(servers)

      updated = servers[0]['resources']['parameters'][0]
      updated['value'].size.should == 1
      updated['value'][0]['name'].should == 'Management Network (1)'
    end

    it 'should only change known network parameters' do
      network = {
        'id' => '1', 'name' => 'Test Network',
        'vlanId' => '28', "static" => 'false'
      }
      ASM::Util.stubs(:fetch_network_settings).returns(network)
      ASM::Util.expects(:reserve_network_ips).never
      
      param = { 'id' => 'unknown_network', 'value' => '1', }
      servers = [ {'id' => 'cert', 'resources' => { 'parameters' => [ param ] } } ]
      @sd.massage_networks!(servers)

      updated = servers[0]['resources']['parameters'][0]
      updated['value'].should == '1'
    end

  end

  describe 'when data is invalid' do

    it 'should warn when no serviceTemplate is defined' do
      @mock_log = mock('foo')
      @sd.expects(:logger).at_least_once.returns(@mock_log)
      @mock_log.stubs(:debug)
      @mock_log.expects(:info).with('Status: Started')
      @mock_log.expects(:info).with('Starting deployment ')
      @mock_log.expects(:warn).with('Service deployment data has no serviceTemplate defined')
      @mock_log.expects(:info).with('Status: Completed')
      @sd.process({})
    end

    it 'should warn when there are no components' do
      @mock_log = mock('foo')
      @sd.expects(:logger).at_least_once.returns(@mock_log)
      @mock_log.stubs(:debug)
      @mock_log.expects(:info).with('Status: Started')
      @mock_log.expects(:info).with('Starting deployment ')
      @mock_log.expects(:warn).with('service deployment data has no components')
      @mock_log.expects(:info).with('Status: Completed')
      @sd.process({'serviceTemplate' => {}})
    end

    it 'should fail when resources do not have types' do
      expect do
        @sd.process({'serviceTemplate' => {'components' => [
          {'id' => 'id', 'puppetCertName' => 'cert', 'type' => 'TEST', 'resources' => [
            {}
          ]}
        ]}})
      end.to raise_error(Exception, 'resource found with no type')
    end

    it 'should fail when resources do not have paremeters' do
      expect do
        @sd.process({'serviceTemplate' => {'components' => [
          {'type' => 'TEST', 'id' => 'id2','puppetCertName' => 'cert2', 'resources' => [
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
          {'type' => 'TEST', 'id' => 'foo', 'puppetCertName' => 'cert4', 'resources' => [
            {'id' => 'user', 'parameters' => []}
          ]}
        ]}})
      end.to raise_error(Exception, 'Component has resource user with no title')
    end
    
  end

  describe 'dealing with duplicate certs in the same deployment' do
    before do
      @counter_files = [File.join(@tmp_dir, 'existing_file.yaml')]
    end
    after do
      @counter_files.each do |f|
        File.delete(f) if File.exists?(f)
      end
    end
    def write_counter_files
      @counter_files.each do |f|
        File.open(f, 'w') do |fh|
          fh.write('stuff') 
        end
      end
    end
    it 'should be able to create file counters labeled 2 when files exist' do
      write_counter_files
      @sd.iterate_resource_file(@counter_files.first).should == File.join(@tmp_dir, 'existing_file___2.yaml')
    end
    it 'should increment existing counter files' do
      @counter_files.push(File.join(@tmp_dir, 'existing_file___4.yaml'))
      write_counter_files
      @sd.iterate_resource_file(@counter_files.first).should == File.join(@tmp_dir, 'existing_file___5.yaml')
    end
    it 'should return passed in file when no file exists' do
      @sd.iterate_resource_file(@counter_files.first).should == File.join(@tmp_dir, 'existing_file.yaml')
    end
  end

  describe 'when checking agent status' do
    before do
      Time.stubs(:now).returns(Time.new("1969-01-01 00:00:00 -0600"))
      
      RestClient.stubs(:get)
        .with(URI.escape("http://localhost:7080/v3/nodes?query=[\"and\", [\"=\", [\"node\", \"active\"], true], [\"=\", \"name\", \"host\"]]]"),
        {:content_type => :json, :accept => :json})
          .returns('[{"name":"host"}]')

      RestClient.stubs(:get)
        .with(URI.escape("http://localhost:7080/v3/reports?query=[\"=\", \"certname\", \"host\"]&order-by=[{\"field\": \"receive-time\", \"order\": \"desc\"}]&limit=1"),
        {:content_type => :json, :accept => :json})
          .returns('[{"receive-time":"1969-01-01 01:00:00 -0600", "hash":"fooreport"}]')
    end

    it 'should be able to detect when a node has checked in' do
      RestClient.stubs(:get)
        .with(URI.encode("http://localhost:7080/v3/events?query=[\"=\", \"report\", \"fooreport\"]"),
        {:content_type => :json, :accept => :json})
         .returns('[{"name":"host"}]')

      ASM::ServiceDeployment.new('123').await_agent_run_completion('host', 10).should be_true
    end

    it 'should raise PuppetEventException if a node has a recent failed event' do
      RestClient.stubs(:get)
        .with(URI.encode("http://localhost:7080/v3/events?query=[\"=\", \"report\", \"fooreport\"]"),
        {:content_type => :json, :accept => :json})
         .returns('[{"name":"host", "status":"failure"}]')


      expect{ASM::ServiceDeployment.new('123').await_agent_run_completion('host', 10)}.to raise_exception(ASM::ServiceDeployment::PuppetEventException)
    end 
  end

  describe 'when checking find related components' do
    before do
      data = JSON.parse(File.read('/opt/asm-deployer/spec/fixtures/find_related_components.json'))['Deployment']
      comp_by_type = @sd.components_by_type(data)
      @sd.set_components_by_type('CLUSTER',  comp_by_type['CLUSTER'] )
      @sd.set_components_by_type('VIRTUALMACHINE',  comp_by_type['VIRTUALMACHINE'] )
      @components = data['serviceTemplate']['components']
    end
    it 'should return related component based on componentID' do
       @sd.find_related_components('CLUSTER', @components[0]).should ==  [{"id"=>"ID1", "componentID"=>"COMPID1", "type"=>"CLUSTER", "relatedComponents"=>{"entry"=>{"key"=>"ID1", "value"=>"Virtual Machine 1"}}, "resources"=>{"id"=>"asm::cluster", "parameters"=>[{"id"=>"datacenter"}]}}]
    end
    it 'should fail to related component based on ID' do
       @sd.find_related_components('VIRTUALMACHINE', @components[1]).should == []
    end
  end

  describe 'verifying service deployer internal configuration' do
    it 'configures directory' do
      @sd.stubs(:create_dir)
      @sd.send(:deployment_dir).should == File.join(@tmp_dir, @sd.id)
      @sd.send(:resources_dir).should == File.join(@tmp_dir, @sd.id, 'resources')
    end
  end
end
