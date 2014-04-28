require 'spec_helper'
require 'asm/device_management'
require 'asm'

describe ASM::DeviceManagement do

  before do
    ASM.init
    @test_dir = Dir.mktmpdir('device_mgmt_test')
    @conf_dir = FileUtils.mkdir("#{@test_dir}/devices").first
    @ssl_dir = FileUtils.mkdir("#{@test_dir}/ssl").first
    @cert_name = "foo-127.0.0.1"

    ASM::Util.send(:remove_const, :DEVICE_CONF_DIR)
    ASM::Util.const_set(:DEVICE_CONF_DIR, @conf_dir)
    ASM::Util.send(:remove_const, :DEVICE_SSL_DIR)
    ASM::Util.const_set(:DEVICE_SSL_DIR, @ssl_dir)

    mock_log = mock('device_management')
    mock_log.stub_everything
    ASM::DeviceManagement.expects(:logger).at_least_once.returns(mock_log)
  end

  after do
    ASM.clear_mutex
    FileUtils.remove_entry_secure @test_dir
  end

  it 'should be able to delete a conf file' do
    conf_file = FileUtils.touch("#{@conf_dir}/#{@cert_name}.conf").first
    ASM::DeviceManagement.remove_device_conf(@cert_name)
    File.exist?(conf_file).should == false
  end

  it 'should be able to delete a device puppet ssl folder' do
    dir_name = @ssl_dir + "/#{@cert_name}"
    dir = FileUtils.mkdir_p(dir_name)
    #Sanity check to ensure proper directory was created
    #ASM::Util.run_command_simple("sudo /opt/Dell/scripts/rm-device-ssl.sh #{device_name}")
    ASM::Util.stubs(:run_command_simple).with("sudo /opt/Dell/scripts/rm-device-ssl.sh #{@cert_name}") do
      FileUtils.rm_rf(dir)
    end.returns(true)
    File.exist?(dir_name).should == true
    ASM::DeviceManagement.remove_device_ssl_dir(@cert_name)
    File.exist?(dir_name).should == false
  end

  it 'should be able to clean up devices if puppet cert is active' do
    conf_file = ASM::Util::DEVICE_CONF_DIR + "/#{@cert_name}.conf"
    ssl_dir = ASM::Util::DEVICE_SSL_DIR + "/#{@cert_name}"

    FileUtils.expects(:rm).with(conf_file).returns(conf_file)
    FileUtils.expects(:rm_rf).with(ssl_dir).returns(ssl_dir)
    ASM::Util.stubs(:run_command_simple).with("sudo /opt/Dell/scripts/rm-device-ssl.sh #{@cert_name}") do
      FileUtils.rm_rf(ssl_dir)
    end.returns(true)

    ASM::Util.stubs(:get_puppet_certs).returns([@cert_name])
    ASM::DeploymentTeardown.expects(:clean_deployment_certs)
      .with([@cert_name])
        .returns(@cert_name)

    ASM::DeviceManagement.remove_device(@cert_name)
    File.exist?(conf_file).should == false
    File.exist?(ssl_dir).should == false
  end
end
