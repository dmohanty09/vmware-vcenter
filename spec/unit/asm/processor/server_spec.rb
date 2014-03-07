require 'spec_helper'
require 'asm/processor/server'

describe ASM::Processor::Server do

  before do
    @data = {
      'asm::server' => {'title' => {

        'product_key' => 'PK',
        'timezone'    => 'Central',
        'ntp'         => 'pool.ntp.org',
        'language'    => 'en-us',
        'keyboard'    => 'en-us',
        'domain_name' => 'aidev',
        'fqdn'        => 'aidev.com',
        'domain_admin_user'     => 'admin',
        'domain_admin_password' => 'pass',
        'os_image_type'         => 'foo',
      }},
      'asm::idrac' => {'title' => {}}
    }
  end


  describe 'when munging resource data for hyperV' do

    it 'should do some stuff' do
      data = subject.munge_hyperv_server('title', @data)
      server_data = data['asm::server']['title']
      idrac_data  = data['asm::idrac']['title']
      # make sure that all old values were munged out of server params
      server_data.size.should == 4
      server_data['os_image_type'].should == 'windows'
      server_data['razor_image'].should    == 'win_hyper_v'
      idrac_data['enable_npar'].should == false
      idrac_data['sysprofile'].should  == 'PerfOptimized'
      
      class_data   = server_data['puppet_classification_data']['hyperv::config']
      install_data = server_data['installer_options']
      class_data.should == {
        'domain_name'           => 'aidev',
        'fqdn'                  => 'aidev.com',
        'domain_admin_user'     => 'admin',
        'domain_admin_password' => 'pass'
      }
      install_data.should == {
        'language'    => 'en-us',
        'keyboard'    => 'en-us',
        'product_key' => 'PK',
        'timezone'    => 'Central',
        'ntp'         => 'pool.ntp.org',
        'os_type'     => 'foo'
      }
    end

  end

end
