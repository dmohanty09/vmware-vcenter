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

        case vm_type
        when 'asm::vm', 'asm::vm::vcenter'
          vm_config.collect{|uuid, vm| VMware.new(vm)}
        when 'asm::vm::scvmm'
          vm_config.collect{|uuid, vm| Scvmm.new(vm)}
        else
          raise ArgumentError, "Invalid VM resource type #{vm_type}"
        end
      end

      class VM_Mash < Hashie::Mash
        def nil?
          !any?
        end

        def to_puppet
          raise NotImplementedError, 'VM_Mash is a not a puppet resource'
        end
      end

      class VMware < VM_Mash
        def process!(certname, server, cluster)
          self.hostname = self.hostname || server.hostname || server.os_host_name
          raise(ArgumentError, 'VM hostname not specified and missing server hostname value') unless self.hostname

          case server['os_image_type']
          when 'windows'
            self.os_type = 'windows'
            self.os_guest_id = 'windows8Server64Guest'
            self.scsi_controller_type = 'LSI Logic SAS'
          else
            self.os_type = 'linux'
            self.os_guest_id = 'rhel6_64Guest'
            self.scsi_controller_type = 'VMware Paravirtual'
          end

          self.cluster = cluster.cluster
          self.datacenter = cluster.datacenter
          self.vcenter_id = certname
          self.vcenter_options = { 'insecure' => true }
          self.ensure = 'present'

          # Default VMware network:
          network = [
            { 'portgroup' => 'VM Network',
              'nic_type' => 'vmxnet3'}
          ]

          self.network_interfaces.each do |net|
            network << { 
              'portgroup' => net['name'],
              'nic_type' => 'vmxnet3'
            }
          end

          self.network_interfaces = network
        end

        def to_puppet
          hostname = self.delete 'hostname'
          { 'asm::vm::vcenter' => { hostname => self.to_hash }}
        end
      end

      class Scvmm < VM_Mash
        def process!(certname, server, cluster)
          hostname = self.delete('name')
          raise(ArgumentError, 'VM hostname not specified, missing server os_host_name value') unless hostname
          self.hostname = hostname

          self.scvmm_server = certname
          self.vm_cluster = cluster.name
          self.ensure = 'present'

          network_default = {
            :ensure => 'present',
            :mac_address_type => 'dynamic',
            :ipv4_address_type => 'dynamic',
            :vlan_enabled => 'true',
            :transport => 'Transport[winrm]',
          }

          networks = {}
          self.network_interfaces.each_with_index do |i, net|
            network = network_default.clone
            vlan_id = net['vlanId']
            raise(ArgumentError, "Missing VLAN id #{vlan}") unless vlan_id
            network['vlan_id'] = vlan_id
            networks["#{hostname}:#{i}"] = network
          end
          self.network_interfaces = networks
        end

        def to_puppet
          hostname = self.delete 'hostname'
          { 'asm::vm::scvmm' => { hostname => self.to_hash }}
        end
      end

    end

    class Server
      def self.create(value)
        if value.include? 'asm::server'
          value['asm::server'].collect do |uuid, data| 
            data['uuid'] = uuid
            ASM::Resource::Mash.new(cleanup(data))
          end
        else
          []
        end
      end

      def self.cleanup(server)
        if server.include? 'os_type'
          server['os_image_type'] = server.delete('os_type')
          # TODO: migrate logger
          #@logger.warn('Server configuration contains deprecated param name os_type')
        end
        server
      end
    end

    module Cluster
      def self.create(value)
        result = []
        value.each do |cluster_type, cluster_config|
          case cluster_type
          when 'asm::cluster', 'asm::cluster::vmware'
            result << ASM::Resource::Cluster::VMware.new(cluster_config)
          when 'asm::cluster::scvmm'
            result << ASM::Resource::Cluster::Scvmm.new(cluster_config)
          end
        end
        result
      end

      class Cluster_Mash < Hashie::Mash
      end

      class VMware < Cluster_Mash
      end

      class Scvmm < Cluster_Mash
      end
    end
  end
end
