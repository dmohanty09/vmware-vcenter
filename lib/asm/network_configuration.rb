require 'asm/errors'
require 'asm/wsman'
require 'hashie'

module ASM

  class NetworkConfiguration

    attr_accessor(:logger)

    def initialize(network_config_hash, logger = nil)
      @mash = Hashie::Mash.new(network_config_hash)
      @logger = logger
      self.munge!
    end

    # Forward methods we don't define directly to the mash
    def method_missing(sym, *args, &block)
      @mash.send(sym, *args, &block)
    end

    class NicInfo

      def initialize(fqdd, logger = nil)
        @mash = parse_fqdd(fqdd, logger)
      end

      # Forward methods we don't define directly to the mash
      def method_missing(sym, *args, &block)
        @mash.send(sym, *args, &block)
      end

      def card_to_fabric(card)
        ['A', 'B', 'C'][card.to_i - 1]
      end

      def parse_fqdd(fqdd, logger)
        ret = Hashie::Mash.new
        # Expected format: NIC.Mezzanine.2B-1-1
        ret.fqdd = fqdd
        (_, ret.type, port_info) = ret.fqdd.split('.')
        (ret.card, ret.port, ret.partition_no) = port_info.split('-')
        if ret.card =~ /([0-9])([A-Z])/
          orig_card = ret.card
          ret.card = $1
          ret.fabric = $2
          expected_fabric = card_to_fabric(orig_card)
          if ret.fabric != expected_fabric
            logger.warn("Mismatched fabric information for #{orig_card}: #{ret.fabric} versus #{expected_fabric}")
          end
        else
          ret.fabric = card_to_fabric(ret.card)
        end
        ret
      end

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
        $1.to_i
      else
        raise(Exception, "Invalid port name #{port_name}")
      end
    end

    def name_to_partition(partition_name)
      if partition_name =~ /([0-9]*)/
        $1.to_i
      else
        raise(Exception, "Invalid partition name #{partition_name}")
      end
    end

    def get_partitions(*network_types)
      @mash.cards.collect do |fabric|
        fabric.interfaces.collect do |port|
          port.partitions.find_all do |partition|
            partition.networkObjects && partition.networkObjects.find do |network|
              network_types.include?(network.type)
            end
          end
        end
      end.flatten
    end

    # Finds all networks of one of the specified network types
    def get_networks(*network_types)
      @mash.cards.collect do |fabric|
        fabric.interfaces.collect do |port|
          port.partitions.collect do |partition|
            partition.networkObjects.find_all do |network|
              network_types.include?(network.type)
            end
          end
        end
      end.flatten.uniq
    end

    # Returns the network object for the given network type.  This method raises
    # an exception if more than one network is found, so it is never valid to
    # call it for network types that may have more than one network associated
    # with them such as iSCSI or public/private lan.
    def get_network(network_type)
      ret = get_networks(network_type)
      uniq_net_name = ret.collect { |n| n.name }.uniq
      if uniq_net_name.size == 1
        ret[0]
      else
        raise(Exception, "There should be only one #{network_type} network but found #{uniq_net_name.size}: #{uniq_net_name}")
      end
    end

    def is_blade?
      @mash.servertype == 'blade'
    end

    def is_rack?
      @mash.servertype == 'rack'
    end

    def munge!
      # Augment partitions with additional info
      source = case @mash.servertype
                 when 'blade'
                   @mash.interfaces = nil
                   @mash.fabrics
                 when 'rack'
                   @mash.fabrics = nil
                   @mash.interfaces
                 else
                   raise(Exception, "Unsupported server type in network configuration: #{@mash.servertype}")
               end

      partition_i = 0
      interface_i = 0
      card_i = 0
      @mash.cards = []
      source.each do |orig_card|
        # For now we are discarding FC interfaces!
        if ASM::Util.to_boolean(orig_card.enabled) && !ASM::Util.to_boolean(orig_card.usedforfc)
          card = Hashie::Mash.new(orig_card)
          card.interfaces = []
          orig_card.interfaces.each do |orig_interface|
            interface = Hashie::Mash.new(orig_interface)
            interface.partitions = []
            port_no = name_to_port(orig_interface.name).to_i
            nic_type = card.nictype.to_i
            max_partitions = case nic_type
                               when 4
                                 # Quad-port nics can have two partitions
                                 2
                               when 2
                                 # Dual-port nics can have 4
                                 4
                               else
                                 # Defaulting to 4...
                                 logger.warn("Unsupported nic type: #{nic_type}") if logger
                                 4
                             end
            if nic_type >= port_no
              orig_interface.interface_index = interface_i
              interface_i += 1
              orig_interface.partitions.each do |partition|
                partition_no = name_to_partition(partition.name)
                if partition_no == 1 || (interface.partitioned && partition_no <= max_partitions)
                  if is_blade?
                    partition.fabric_letter = name_to_fabric(card.name)
                  end
                  partition.port_no = port_no
                  partition.partition_no = partition_no
                  partition.partition_index = partition_i
                  partition_i += 1

                  interface.partitions.push(partition)
                end
              end
              card.interfaces.push(interface)
            end
          end
          card.card_index = card_i
          card_i += 1
          @mash.cards.push(card)
        end
      end
    end

    def build_index_to_slot_hash(nics)
      slots = nics.collect { |nic| nic.card.to_i }.compact.sort.uniq

      unless slots.size >= @mash.cards.size
        fqdds = nics.collect { |nic| nic.fqdd }
        logger.debug("Found nic fqdd's: #{fqdds}") if logger
        raise(ASM::UserException, "Network configuration requires #{@mash.cards.size} network cards but only #{slots.size} were found")
      end

      ret = {}
      @mash.cards.collect { |card| card.card_index }.each do |i|
        ret[i] = slots[i]
      end
      ret
    end

    def add_nics!(endpoint)
      nics = get_wsman_nic_info(endpoint)

      @mash.cards.each do |card|
        card.interfaces.each do |interface|
          interface.partitions.each do |partition|
            nic = nics.find do |n|
              if is_blade?
                (name_to_fabric(card.name) == n.fabric &&
                    name_to_port(interface.name).to_s == n.port &&
                    name_to_partition(partition.name).to_s == n.partition_no)
              else
                slot_map ||= build_index_to_slot_hash(nics)
                slot = slot_map[card.card_index] or raise(Exception, "No slot found for card_index #{card.card_index} in #{slot_map}")
                (slot.to_s == n.card &&
                    name_to_port(interface.name).to_s == n.port &&
                    name_to_partition(partition.name).to_s == n.partition_no)
              end
            end

            if nic
              partition.nic = nic
              partition.fqdd = nic.fqdd
              partition.mac_address = nic.mac_address
            else
              msg = "Mac address not found on #{endpoint.host} for #{card.name} #{interface.name} partition #{partition.name}"
              raise(Exception, msg)
            end
          end
        end
      end
    end

  end
end
