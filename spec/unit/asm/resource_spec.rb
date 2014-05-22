require 'spec_helper'
require 'rbvmomi'
require 'asm/resource'

describe ASM::Resource::VM do

  it 'reject bad VMs' do
    data = [
      {'asm::vm::vmware' =>  {'id' => {}}}
    ]  
    data.each do |i|
      expect{ASM::Resource::VM.create(i)}.to raise_error
    end
  end

  context 'VMware VMs' do
    before :each do
      conf = Hashie::Mash.new(
        :host => 'localhost',
        :user => 'admin',
        :password => 'password',
      )
      ASM::Util.stubs(:parse_device_config).returns(conf)
      @server = Hashie::Mash.new
      @cluster = Hashie::Mash.new({'cluster' => 'dc_cluster'})
    end

    it 'creates VMs' do
      data = [
        {'asm::vm' =>  {'id' => {}}},
        {'asm::vm::vcenter' => {'id' => {}}}
      ]  
      data.each do |i|
        vms = ASM::Resource::VM.create(i)
        expect(vms.first.is_a? ASM::Resource::VM::VMware).to be true
      end
    end

    it 'transforms windows vm to puppet' do
      data = {
        'asm::vm' => {
          'win2k8' => {
            'os_image_type' => 'windows', 
            'hostname' => 'vm-win2k8r2',
            'network_interfaces' => {},
          }
        }
      }
      vm = ASM::Resource::VM.create(data).first
      @server.os_image_type = 'windows' 
      vm.process!('vm-win2k8r2', @server, @cluster)
      result = {
        "asm::vm::vcenter"=> {
          "vm-win2k8r2"=> {
            "os_image_type"=>"windows",
            "network_interfaces"=> [{"portgroup"=>"VM Network", "nic_type"=>"vmxnet3"}],
            "os_type"=>"windows",
            "os_guest_id"=>"windows8Server64Guest",
            "scsi_controller_type"=>"LSI Logic SAS",
            "cluster"=>"dc_cluster",
            "datacenter"=>nil,
            "vcenter_id"=>"vm-win2k8r2",
            "vcenter_options"=>{"insecure"=>true},
            "ensure"=>"present"
          }
        }
      }
      expect(vm.to_puppet).to eq(result)
    end

    it 'transforms linux vm to puppet' do
      data = {
        'asm::vm' => {
          'linux' => {
            'os_image_type' => 'linux', 
            'hostname' => 'vm-rhel6',
            'network_interfaces' => {},
          }
        }
      }
      vm = ASM::Resource::VM.create(data).first
      @server.os_image_type = 'linux' 
      vm.process!('vm-rhel6', @server, @cluster)
      result = {
        "asm::vm::vcenter"=> {
          "vm-rhel6"=> {
            "os_image_type"=>"linux",
            "network_interfaces"=> [{"portgroup"=>"VM Network", "nic_type"=>"vmxnet3"}],
            "os_type"=>"linux",
            "os_guest_id"=>"rhel6_64Guest",
            "scsi_controller_type"=>"VMware Paravirtual",
            "cluster"=>"dc_cluster",
            "datacenter"=>nil,
            "vcenter_id"=>"vm-rhel6",
            "vcenter_options"=>{"insecure"=>true},
            "ensure"=>"present"
          }
        }
      }
      expect(vm.to_puppet).to eq(result)
    end
  end

  context 'HyperV VMs' do
    it 'creates hyperv vm' do
      data = [
        {'asm::vm::scvmm' => {'id' =>{}}}
      ]  
      data.each do |i|
        vms = ASM::Resource::VM.create(i)
        expect(vms.first.is_a? ASM::Resource::VM::Scvmm).to be true
      end
    end
  end
end

describe ASM::Resource::Server do
  context 'Windows Server' do
    it 'creates windows vm' do
      data = {
        'asm::server' => {
          'title' => {
            'product_key' => 'aaaa-bbbb-cccc-dddd-eeee',
            'os_host_name' => 'win2k8',
            'os_image_type' => 'windows',
            'os_image_version' => 'win2012r2standard',
          }
        }
      }
      server = ASM::Resource::Server.create(data).first
      ASM::Util.stubs(:hostname_to_certname).returns('certname')
      server.process!('H8YDL9', '12345890', 1)

      result = {
        "title" => {
          "os_host_name" => 'win2k8',
          "os_image_type"=>"windows",
          "os_image_version"=>"win2012r2standard",
          "rule_number"=>"12345890",
          "broker_type"=>"puppet",
          "serial_number"=>"H8YDL9",
          "policy_name"=>"policy-win2k8-1",
          "cert_name"=>"certname",
          "installer_options"=>{"product_key"=>"aaaa-bbbb-cccc-dddd-eeee"},
        }
      }

      expect(server.to_puppet).to eq(result)
    end
  end
end
