require 'spec_helper'
require 'asm/update_deployment'
require 'asm/deployment_teardown'
require 'asm'
require 'tmpdir'

describe ASM::UpdateDeployment do

  before do
    ASM.init
    @test_dir = Dir.mktmpdir('update_deployment_spec')
    FileUtils.cp_r(File.expand_path("../../../fixtures/deployments", __FILE__), @test_dir)
    ASM.stubs(:base_dir).returns("#{@test_dir}/deployments")
    ASM::Util.stubs(:reserve_network_ips).returns(["172.23.119.2"])
    ASM::Util.stubs(:release_network_ips)
    mock_command_result = { 
      'stdout' => '', 'stderr' => '', 'exit_status' => 0, 'pid' => 0,
    }
    ASM::Util.stubs(:run_command_simple).returns(mock_command_result)
    ASM::Util.stubs(:run_command)
    fetch_network_settings = {
      "id"=>"ff808081452c813b01452cee4a3f0066",
      "name"=>"vMotion",
      "description"=>"",
      "type"=>"HYPERVISOR_MANAGEMENT",
      "vlanId"=>23,
      "staticNetworkConfiguration"=>
        {"gateway"=>"172.23.0.1",
         "subnet"=>"255.255.0.0",
         "ipRange"=>
           [{"id"=>"ff808081452c813b01452cee4a460067",
             "startingIp"=>"172.23.119.1",
             "endingIp"=>"172.23.119.100"}]},
      "createdDate"=>"2014-04-04T13:29:45.239+0000",
      "createdBy"=>"admin",
      "link"=>
        {"title"=>"vMotion",
         "href"=>
         "http://localhost:9080/VirtualServices/Network/ff808081452c813b01452cee4a3f0066",
         "rel"=>"self"},
         "static"=>true
    }
    populate_blade_switch_hash = {
      "dell_iom-172.17.15.234"=>
        {"connection_url"=>nil, 
         "device_type"=>"dell_powerconnect"
        },
      "dell_iom-172.17.15.237"=>
        {"connection_url"=>nil, 
         "device_type"=>"dell_powerconnect"}
    }
    ASM::ServiceDeployment.any_instance.stubs(:populate_blade_switch_hash).returns(populate_blade_switch_hash)
    ASM::Util.stubs(:fetch_network_settings).returns(fetch_network_settings)
    ASM::Util.stubs(:fetch_server_inventory).returns({"serverType"=>"BLADE","serviceTag"=>"1FQSGT1","model"=>"PowerEdge M620"})
    ASM::ServiceDeployment.any_instance.stubs(:process_tor_switches).returns(nil)
    ASM::ServiceDeployment.any_instance.stubs(:process_san_switches).returns(nil)
    ASM::ServiceDeployment.any_instance.stubs(:process_components).returns(nil)
  end

  after do
    ASM.clear_mutex
    FileUtils.rm_rf(@test_dir)
  end

  it 'should be able to update a deployment' do
    deployment_id = 'ff808081452c813b01453c4b14e80751'
    dir = File.join(ASM::base_dir, deployment_id)
    deployment = JSON.parse(File.new(dir + "/deployment.json").read)
    deployment['Deployment']['debug'] = 'true'
    ASM.retry_deployment('ff808081452c813b01453c4b14e80751', deployment)
    deployment = JSON.parse(File.new(dir + "/deployment.json").read)
    deployment['Deployment']['jobStatus'].should eq('SUCCESSFUL')
  end

  it 'should be able to find previous deployments' do
    deployment_id = 'ff808081452c813b01453c4b14e80751'
    dir = File.join(ASM::base_dir, deployment_id)
    Dir.mkdir("#{dir}/1")
    FileUtils.cp("#{dir}/deployment.json", "#{dir}/1/deployment.json")
    ASM::DeploymentTeardown.get_previous_deployment_certs('ff808081452c813b01453c4b14e80751').should eq(['agent-devlinuxhost1'])
  end

end
