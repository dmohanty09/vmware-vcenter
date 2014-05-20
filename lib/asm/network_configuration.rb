require 'asm/wsman'
require 'hashie'

module ASM

  class NetworkConfiguration < Hashie::Mash

    class NicInfo < Hashie::Mash

      def initialize(fqdd, logger = nil)
        parse_fqdd!(fqdd, logger)
      end

      def card_to_fabric(card)
        ['A', 'B', 'C'][card.to_i - 1]
      end

      def parse_fqdd!(fqdd, logger)
        # Expected format: NIC.Mezzanine.2B-1-1
        self.fqdd = fqdd
        (_, self.type, port_info) = self.fqdd.split('.')
        (self.card, self.port, self.partition_no) = port_info.split('-')
        if self.card =~ /([0-9])([A-Z])/
          orig_card = self.card
          self.card = $1
          self.fabric = $2
          expected_fabric = card_to_fabric(orig_card)
          if self.fabric != expected_fabric
            logger.warn("Mismatched fabric information for #{orig_card}: #{self.fabric} versus #{expected_fabric}")
          end
        else
          self.fabric = card_to_fabric(self.card)
        end
      end

    end

    attr_accessor(:logger)

    def initialize(network_config_hash, logger = nil)
      super.initialize(network_config_hash)
      @logger = logger
    end

    def get_wsman_nic_info(endpoint)
      fqdd_to_mac = ASM::WsMan.get_mac_addresses(endpoint, logger)
      fqdd_to_mac.keys.map do |fqdd|
        nic = NicInfo.new(fqdd, logger)
        nic.mac_address = fqdd_to_mac[fqdd]
        nic
      end
    end

    def name_to_fabric(fabric_name)
      if fabric_name =~ /Fabric ([A-Z])/
        $1
      else
        raise(Exception, "Invalid fabric name #{fabric_name}")
      end
    end

    def name_to_port(port_name)
      if port_name =~ /Port ([0-9]*)/
        $1
      else
        raise(Exception, "Invalid port name #{port_name}")
      end
    end

    def name_to_partition(partition_name)
      if partition_name =~ /([0-9]*)/
        $1
      else
        raise(Exception, "Invalid partition name #{partition_name}")
      end
    end

    def get_partitions(*network_types)
      self.fabrics.collect do |fabric|
        fabric.interfaces.collect do |port|
          port.partitions.find_all do |partition|
            partition.networkObjects && partition.networkObjects.find do |network|
              network_types.include?(network.type)
            end
          end
        end
      end.flatten
    end

    def add_partition_info!
      # Augment partitions with additional info
      partition_i = 0
      self.fabrics.each do |fabric|
        if ASM::Util.to_boolean(fabric.enabled)
          fabric.interfaces.each do |port|
            port.partitions.each do |partition|
              partition.fabric_letter = name_to_fabric(fabric.name)
              partition.port_no = name_to_port(port.name)
              partition.partition_no = name_to_partition(partition.name)
              partition.partition_index = partition_i
              partition_i += 1
            end
          end
        end
      end
    end

    def add_nics!(endpoint)
      nics = get_wsman_nic_info(endpoint)
      self.fabrics.each do |fabric|
        fabric.interfaces.each do |port|
          port.partitions.each do |partition|
            # HACK: It is currently impossible to tell which partitions the user
            # has selected versus those that were not visible to the user. For
            # now we only tread partitions with networks as "selected"
            if partition.networkObjects && !partition.networkObjects.empty?
              if partition.name == '1' || port.partitioned
                nic = nics.find do |n|
                  (name_to_fabric(fabric.name) == n.fabric &&
                      name_to_port(port.name) == n.port &&
                      name_to_partition(partition.name) == n.partition_no)
                end

                if nic
                  partition.nic = nic
                  partition.fqdd = nic.fqdd
                  partition.mac_address = nic.mac_address
                else
                  msg = "Mac address not found on #{endpoint.host} for #{fabric.name} #{port.name} partition #{partition.name}"
                  raise(Exception, msg)
                end
              end
            end
          end
        end
      end
    end

  end
end
