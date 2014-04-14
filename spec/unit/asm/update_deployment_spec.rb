require 'spec_helper'
require 'asm/update_deployment'
require 'asm/deployment_teardown'
require 'asm'
require 'tmpdir'

describe ASM::UpdateDeployment do

  before do
    ASM.init
    @test_dir = Dir.mktmpdir('update_deployment_spec')
    FileUtils.cp_r('/opt/asm-deployer/spec/fixtures/deployments', @test_dir)
    ASM.stubs(:base_dir).returns("#{@test_dir}/deployments")
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
