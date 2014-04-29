require 'hashie'
require 'yaml'
require 'json'

module ASM
  module Resource
    class Mash < Hashie::Mash
    end

    module VM
      def self.create(value)
        # TODO: need to migrate log
        # require 'asm/log'
        # log("Processing component: #{value['puppetCertName']}")
        vm_hash = value.select{|k| ['asm::vm', 'asm::vm::vcenter', 'asm::vm::scvmm'].include? k}
        vm_type, vm_config = vm_hash.shift
        vm_config ||= []

        # For simplicity we require exactly one asm::vm::* resource
        raise(ArgumentError, 'Exactly one set of VM configuration accepted, multiple configuration recieved.') unless vm_config.size == 1

        case vm_type
        when 'asm::vm', 'asm::vm::vcenter'
          vm_config.collect{|vm| VMware.new(vm)}
        when 'asm::vm::scvmm'
          vm_config.collect{|vm| Scvmm.new(vm)}
        else
          raise ArgumentError, "Invalid VM resource type #{vm_type}"
        end
      end

      class VM_Mash < Hashie::Mash
        def initialize(source_hash = nil, default = nil, &blk)
          validate(source_hash)
        end

        def nil?
          any?
        end

        def validate(value)
          raise(ArgumentException, 'VM hostname not specified') unless value.include? 'hostname'
        end

        def to_puppet!
          raise NotImplementedError, 'VM_Mash is a not a puppet resource'
        end
      end

      class VMware < VM_Mash
        def process(certname, server, cluster)
          case server.os_image_type
          when 'windows'
            self.os_type = 'windows'
            self.os_guest_id = 'windows8Server64Guest'
            self.scsci_controller_type = 'LSI Logic SAS'
          else
            self.os_type = 'linux'
            self.os_guest_id = 'rhel6_64Guest'
            self.scsi_controller_type = 'VMware Paravirtual'
          end

          self.cluster = cluster.cluster
          self.datacenter = cluster.datacenter
          self.vcenter_id = centername
          self.vcenter_options = { 'insecure' => true }
          self.ensure = 'present'

          # Default VMware network:
          network = [
            { 'portgroup' => 'VM Network',
              'nic_type' => 'vmxnet3'}
          ]

          self.network_interfaces.split(',').compact do |portgroup|
            network << { 
              'portgroup' => portgroup, 
              'nic_type' => 'vmxnet3'
            }
          end

          self.network_interfaces = network
        end

        def to_puppet!(hostname)
          { 'asm::vm::vcenter' => self.to_hash }
        end
      end

      class Scvmm < VM_Mash
        def to_puppet!(hostname)
          { 'asm::vm::scvmm' => self.to_hash }
        end
      end

    end

    class Server
      def self.create(value)
        if value.include? 'asm::server'
          value['asm::server'].collect{|server| ASM::Resource::Mash.new(server)}
        else
          []
        end
      end
    end
  end
end
