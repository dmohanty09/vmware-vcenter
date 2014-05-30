require 'hashie'
require 'yaml'
require 'json'
require 'asm/util'

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

        # This is purely for testing:
        def conf(cert)
          @conf ||= ASM::Util.parse_device_config(cert)
        end

        def to_puppet
          raise NotImplementedError, 'VM_Mash is a not a puppet resource'
        end
      end

      class VMware < VM_Mash
        def process!(cert, server, cluster)
          self.hostname = self.hostname || server.hostname || server.os_host_name
          raise(ArgumentError, 'VM hostname not specified and missing server hostname value') unless self.hostname

          server ||= {}
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
          conf(cluster.title)
          self.cluster = cluster.cluster
          self.datacenter = cluster.datacenter
          self.vcenter_id = cert
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
          @hostname = self.hostname
          hostname = self.delete 'hostname'
          { 'asm::vm::vcenter' => { hostname => self.to_hash }}
        end

        def certname
          if self.source
            "vm#{macaddress.downcase}"
          elsif @hostname
            ASM::Util.hostname_to_certname(@hostname)
          else
            raise Exception, "Unable to determine certname without source or hostname"
          end
        end

        def macaddress
          value = vm.guest.net.first.macAddress
          value.gsub(':', '')
        end

        def vm
          @vm ||= findvm(dc.vmFolder, (self.hostname||@hostname)) 
        end

        def findvm(folder, name)
          folder.children.each do |subfolder|
            break if @vm_obj
            case subfolder 
            when RbVmomi::VIM::Folder
              findvm(subfolder,name)
            when RbVmomi::VIM::VirtualMachine
              @vm_obj = subfolder if subfolder.name == name
            when RbVmomi::VIM::VirtualApp
              @vm_obj = subfolder.vm.find{|vm| vm.name == name }
            else
              raise(Exception, "Unknown child type: #{subfolder.class}")
            end
          end
          @vm_obj
        end

        def dc
          @dc||= vim.serviceInstance.find_datacenter(self.datacenter)
        end

        def vim
          @vim ||= begin
            require 'rbvmomi'
            raise(Exception, "Resource has not been processed.") unless @conf

            options = {
              :host => @conf.host,
              :user => @conf.user,
              :password => @conf.password,
              :insecure => true,
            }
            RbVmomi::VIM.connect(options)
          end
        end
      end

      class Scvmm < VM_Mash
        def process!(cert, server, cluster)
          self.hostname ||= self.delete('name')
          raise(ArgumentError, 'VM hostname not specified, missing server os_host_name value') unless self.hostname

          conf(cluster.title)
          self.scvmm_server = cert
          self.vm_cluster = cluster.name
          self.ensure = 'present'

          network_default = {
            :ensure => 'present',
            :mac_address_type => 'static',
            :mac_address => '00:00:00:00:00:00', 
            :ipv4_address_type => 'dynamic',
            :vlan_enabled => 'true',
            :transport => 'Transport[winrm]',
          }

          networks = {}

          self.network_interfaces.each_with_index do |net, i|
            network = network_default.clone
            vlan_id = net['vlanId']
            raise(ArgumentError, "Missing VLAN id #{vlan}") unless vlan_id
            network['vlan_id'] = vlan_id
            networks["#{hostname}:#{i}"] = network
          end
          self.network_interfaces = networks
        end

        def to_puppet
          @hostname = self.hostname
          hostname = self.delete 'hostname'

          self.each do |key, val|
            self.delete key if val.nil? or val == ''
          end
          { 'asm::vm::scvmm' => { hostname => self.to_hash }}
        end

        def certname
          if self.template
            "vm#{macaddress.downcase}"
          elsif self.hostname
            ASM::Util.hostname_to_certname(self.hostname)
          else
            raise Exception, "Unable to determine certname without source or hostname"
          end
        end

        def macaddress
          raise(Exception, "Resource has not been processed.") unless @conf
          cmd = File.join(File.dirname(__FILE__),'scvmm_macaddress.rb')
          domain, user = @conf.user.split('\\')

          # Workaround bundler JRuby gems intefering:
          # https://groups.google.com/forum/#!topic/ruby-bundler/UufhzrliWfo
          result = ''
          Bundler.with_clean_env do
            result = ASM::Util.run_command_success("#{cmd} -u '#{user}' -d '#{domain}' -p '#{@conf.password}' -s #{@conf.host} -v #{self.hostname||@hostname}")
          end
          result = result.stdout.each_line.collect{|line| line.chomp.rstrip.gsub(':', '')}
          macaddress = result.find{|x| x =~ /^[0-9a-fA-F]{12}$/}
          raise(Exception, 'Virtual machine needs to power on first.') if macaddress == '00000000000000'
          macaddress
        end
      end
    end

    class Server_Mash < Hashie::Mash
      def initialize(server, default=nil, &blk)
        if server.include? 'os_type'
          server['os_image_type'] = server.delete('os_type')
        end
        super(server, default, &blk)
      end

      def process!(serial_number, rule_number, id, classes={})
        if self.include? 'rule_number'
          raise(Exception, "Did not expect rule_number in asm::server")
        else
          self.rule_number = rule_number
        end

        if self.os_image_type == 'vmware_esxi'
          self.broker_type = 'noop'
        else
          self.broker_type = 'puppet'
        end

        hostname = self.os_host_name

        # For OS without os_image_version such as Linux, ESX
        self.os_image_version ||= self.os_image_type

        self.serial_number = serial_number
        self.policy_name = "policy-#{hostname}-#{id}"

        self.cert_name = ASM::Util.hostname_to_certname(hostname)
        self.puppet_classification_data = classes unless classes.empty?
      end

      def to_puppet
        title = self.delete 'title'
        case self.os_image_type
        when 'windows'
          installer_options = {}
	  [
	    'language',
	    'keyboard',
	    'product_key',
	    'timezone',
	  ].each do |param|
            installer_options[param] = self.delete(param) if self.include?(param)
          end
          self.installer_options = installer_options
        end

        { title => self.to_hash }
      end
    end

    class Server
      def self.create(value)
        if value.include? 'asm::server'
          value['asm::server'].collect do |title, server| 
            server['title'] = title
            ASM::Resource::Server_Mash.new(server)
          end
        else
          []
        end
      end

      def self.cleanup(server, title)
        server['title'] = title 
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
