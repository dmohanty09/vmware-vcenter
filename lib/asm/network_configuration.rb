require 'asm/errors'
require 'asm/wsman'
require 'hashie'

module ASM

  # The NetworkConfiguration class is a wrapper class to make it easier to work
  # with the networking data generated by the ASM GUI.
  #
  # The data format is different for blades and racks. Both cases contain
  # lists of interfaces (ports) and partitions. However in the blade case
  # the interfaces are contained in the fabrics field and in the rack case
  # there is another top-level field called interfaces (really cards) that
  # contains the inner # interfaces (ports).
  #
  # Some other oddities to note about this data:
  #
  # - fabrics are always present even for the rack server case. The fields
  #   are simply not populated with data.
  #
  # - partitions greater than one are present even when an interface is not
  #   partitioned.
  #
  # To make the data more uniform this class provides a virtual cards field
  # which can be used instead of fabrics or interfaces. It is populated for both
  # the rack and blade case and has irrelevant data (fabrics / interfaces that
  # are not enabled, partitions when the interface is not partitioned, etc.)
  # stripped out. All partitions can be uniformly iterated over with something
  # like:
  #
  # nc = ASM::NetworkConfiguration.new(params['network_configuration'])
  # nc.cards.each do |card|
  #   card.each do |interface|
  #     interface.each do |partition|
  #       networks = partion.networkObjects
  #       # ... do whatever
  #     end
  #   end
  # end
  #
  # See the add_nics! method for a way to tie the network configuration data
  # directly to the physical nics / ports / partitions.
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

      # Create a new NicInfo based off self but with a different partition
      def create_with_partition(partition)
        NicInfo.new(@mash.fqdd.gsub(/[-]\d+$/, "-#{partition}"))
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
      if ret.size == 1
        ret[0]
      else
        raise(Exception, "There should be only one #{network_type} network but found #{ret.size}: #{ret.collect { |n| n.name }}")
      end
    end

    def get_static_ips(*network_types)
      get_networks(*network_types).collect do |network|
        if ASM::Util.to_boolean(network.static)
          network.staticNetworkConfiguration.ipAddress
        end
      end.compact
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

    # Add nic, fqdd and mac_address fields to the partition data. This info
    # is obtained by calling WsMan to get the NicInfo.
    #
    # By default an exception is raised if nic info is not found for a
    # partition; however if options[:add_partitions] is set to true, nic
    # and fqdd fields will be generated for partition numbers greater than one
    # based off of the partition 1 fqdd. This allows the partitions to be used
    # directly for generating partitioned config.xml data even when the server
    # nics are not currently partitioned.
    def add_nics!(endpoint, options = {})
      options = { :add_partitions => false }.merge(options)
      nics = get_wsman_nic_info(endpoint)

      @mash.cards.each do |card|
        card.interfaces.each do |interface|
          interface.partitions.each do |partition|
            partition_no = name_to_partition(partition.name)
            nic = nics.find do |n|
              if is_blade?
                (name_to_fabric(card.name) == n.fabric &&
                    name_to_port(interface.name).to_s == n.port &&
                    partition_no.to_s == n.partition_no)
              else
                slot_map ||= build_index_to_slot_hash(nics)
                slot = slot_map[card.card_index] or raise(Exception, "No slot found for card_index #{card.card_index} in #{slot_map}")
                (slot.to_s == n.card &&
                    name_to_port(interface.name).to_s == n.port &&
                    partition_no.to_s == n.partition_no)
              end
            end

            if nic
              partition.nic = nic
            elsif options[:add_partitions]
              nic = interface.partitions.first.nic
              partition.nic = nic.create_with_partition(partition_no)
            else
              msg = "Mac address not found on #{endpoint.host} for #{card.name} #{interface.name} partition #{partition.name}"
              raise(Exception, msg)
            end

            partition.fqdd = partition.nic.fqdd
            partition.mac_address = partition.nic.mac_address
          end
        end
      end
    end

  end
end
