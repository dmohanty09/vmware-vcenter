require 'spec_helper'
require 'asm/processor/server'

describe ASM::Processor::Server do

  before do
    @net_config = mock('network_configuration')
    @net_config.stubs(:get_network).with('HYPERVISOR_MANAGEMENT').returns(
        Hashie::Mash.new({:name => 'HypMan', :vlanId => 28, :static => true,
                          :staticNetworkConfiguration => {
                              :gateway => '172.28.0.1', :netmask => '255.255.0.0',
                              :ipAddress => '172.28.15.162', :primaryDns => '172.20.0.8',
                          }
                         }))
    @net_config.stubs(:get_network).with('HYPERVISOR_MIGRATION').returns(
        Hashie::Mash.new({:name => 'LiveMigration', :vlanId => 23, :static => true,
                          :staticNetworkConfiguration => {
                              :gateway => '172.23.0.1', :netmask => '255.255.0.0',
                              :ipAddress => '172.23.15.101',
                          }
                         }))
    @net_config.stubs(:get_network).with('HYPERVISOR_CLUSTER_PRIVATE').returns(
        Hashie::Mash.new({:name => 'ClusterPriCP', :vlanId => 24, :static => true,
                          :staticNetworkConfiguration => {
                              :gateway => '172.24.0.1', :netmask => '255.255.0.0',
                              :ipAddress => '172.24.15.204',
                          }
                         }))
    @net_config.stubs(:get_networks).with('STORAGE_ISCSI_SAN').returns(
            [Hashie::Mash.new({:name => 'iSCSI', :vlanId => 16, :static => true,
                              :staticNetworkConfiguration => {
                                  :gateway => '172.16.0.1', :netmask => '255.255.0.0',
                                  :ipAddress => '172.16.15.162',
                              }}),
             Hashie::Mash.new({:name => 'iSCSI', :vlanId => 16, :static => true,
              :staticNetworkConfiguration => {
                  :gateway => '172.16.0.1', :netmask => '255.255.0.0',
                  :ipAddress => '172.16.15.163',
              }}),])

    ASM::NetworkConfiguration.stubs(:new).returns(@net_config)
    @data = {
      'asm::server' => {'title' => {
        'product_key'           => 'PK',
        'timezone'              => 'Central',
        'ntp'                   => 'pool.ntp.org',
        'language'              => 'en-us',
        'keyboard'              =>  'en-us',
        'domain_name'           => 'aidev',
        'fqdn'                  => 'aidev.com',
        'razor_image'           => 'hyperV2',
        'os_host_name'          => 'foo.bar.baz',
        'os_image_type'         => 'foo',
        'domain_admin_user'     => 'admin',
        'domain_admin_password' => 'pass',
      }},
      'asm::idrac' => {'title' => {}},
      'asm::esxiscsiconfig' => {'title' => {
        'network_configuration' => 'foo',
    }}
    }
  end


  describe 'when munging resource data for hyperV' do
    it 'should do some stuff' do
      data = subject.munge_hyperv_server('title', @data, '127.0.0.1', [], nil, false)
      server_data = data['asm::server']['title']
      idrac_data  = data['asm::idrac']['title']
      # make sure that all old values were munged out of server params
      server_data.size.should == 6
      server_data['os_image_type'].should == 'windows'
      server_data['cert_name'].should == 'agent-foo'

      server_data['razor_image'].should    == 'hyperV2'
      idrac_data['enable_npar'].should == false
      idrac_data['system_profile'].should  == 'PerfOptimized'
      
      class_data   = server_data['puppet_classification_data']['hyperv::config']
      install_data = server_data['installer_options']
      class_data.should == {
        'domain_name'             => 'aidev',
        'fqdn'                    => 'aidev.com',
        'domain_admin_user'       => 'admin',
        'domain_admin_password'   => 'pass',
        'ntp'                     => 'pool.ntp.org',
        'iscsi_target_ip_address' => '127.0.0.1',
        'iscsi_volumes'           => [],
        'ASM::Processor::Server_gateway' => '172.24.0.1',
        'ASM::Processor::Server_ip_address' => '172.24.15.204',
        'ASM::Processor::Server_netmask' => nil,
        'ASM::Processor::Server_vlan_id' => 24,
        'hyperv_diskpart' => false,
        'iscsi_fabric' => 'Fabric A',
        'iscsi_ip_addresses' => ['172.16.15.162', '172.16.15.163'],
        'iscsi_netmask' => nil,
        'iscsi_vlan_id' => 16,
      }
      install_data.should == {
        'language'    => 'en-us',
        'keyboard'    => 'en-us',
        'product_key' => 'PK',
        'timezone'    => 'Central',
        'os_type'     => 'foo'
      }
    end

  end

end
