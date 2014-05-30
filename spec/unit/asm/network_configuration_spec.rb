require 'spec_helper'
require 'asm/network_configuration'

describe ASM::NetworkConfiguration do

  describe 'when parsing NIC FQDDs' do

    # Blade examples:
    #
    # NIC.Integrated.1-1-1: 24:B6:FD:F9:FC:42
    # NIC.Integrated.1-1-2: 24:B6:FD:F9:FC:46
    # NIC.Integrated.1-1-3: 24:B6:FD:F9:FC:4A
    # NIC.Integrated.1-1-4: 24:B6:FD:F9:FC:4E
    # NIC.Integrated.1-2-1: 24:B6:FD:F9:FC:44
    # NIC.Integrated.1-2-2: 24:B6:FD:F9:FC:48
    # NIC.Integrated.1-2-3: 24:B6:FD:F9:FC:4C
    # NIC.Integrated.1-2-4: 24:B6:FD:F9:FC:50
    # NIC.Mezzanine.2B-1-1: 00:10:18:DC:C4:80
    # NIC.Mezzanine.2B-1-2: 00:10:18:DC:C4:84
    # NIC.Mezzanine.2B-1-3: 00:10:18:DC:C4:88
    # NIC.Mezzanine.2B-1-4: 00:10:18:DC:C4:8C
    # NIC.Mezzanine.2B-2-1: 00:10:18:DC:C4:82
    # NIC.Mezzanine.2B-2-2: 00:10:18:DC:C4:86
    # NIC.Mezzanine.2B-2-3: 00:10:18:DC:C4:8A
    # NIC.Mezzanine.2B-2-4: 00:10:18:DC:C4:8E
    #
    # Rack exmaples:
    #
    # NIC.Slot.2-1-1: 00:0A:F7:06:88:50
    # NIC.Slot.2-1-2: 00:0A:F7:06:88:54
    # NIC.Slot.2-1-3: 00:0A:F7:06:88:58
    # NIC.Slot.2-1-4: 00:0A:F7:06:88:5C
    # NIC.Slot.2-2-1: 00:0A:F7:06:88:52
    # NIC.Slot.2-2-2: 00:0A:F7:06:88:56
    # NIC.Slot.2-2-3: 00:0A:F7:06:88:5A
    # NIC.Slot.2-2-4: 00:0A:F7:06:88:5E

    it 'should parse NIC.Integrated.1-1-1' do
      fqdd = ASM::NetworkConfiguration::NicInfo.new('NIC.Integrated.1-1-1')
      fqdd.type.should == 'Integrated'
      fqdd.card.should == '1'
      fqdd.fabric.should == 'A'
      fqdd.port.should == '1'
      fqdd.partition_no.should == '1'
    end

    it 'should parse NIC.Integrated.1-2-3' do
      fqdd = ASM::NetworkConfiguration::NicInfo.new('NIC.Integrated.1-2-3')
      fqdd.type.should == 'Integrated'
      fqdd.card.should == '1'
      fqdd.fabric.should == 'A'
      fqdd.port.should == '2'
      fqdd.partition_no.should == '3'
    end

    it 'should parse NIC.Mezzanine.2B-2-4' do
      fqdd = ASM::NetworkConfiguration::NicInfo.new('NIC.Mezzanine.2B-2-4')
      fqdd.type.should == 'Mezzanine'
      fqdd.card.should == '2'
      fqdd.fabric.should == 'B'
      fqdd.port.should == '2'
      fqdd.partition_no.should == '4'
    end

    it 'should be confused by NIC.Mezzanine.2C-2-4' do
      @logger = mock('NIC.Mezzanine.2C-2-4')
      @logger.expects(:warn)
      fqdd = ASM::NetworkConfiguration::NicInfo.new('NIC.Mezzanine.2C-2-4', @logger)
      fqdd.type.should == 'Mezzanine'
      fqdd.card.should == '2'
      fqdd.fabric.should == 'C'
      fqdd.port.should == '2'
      fqdd.partition_no.should == '4'
    end

    it 'should parse rack fqdd in port 1' do
      fqdd = ASM::NetworkConfiguration::NicInfo.new('NIC.Slot.2-1-1')
      fqdd.type.should == 'Slot'
      fqdd.card.should == '2'
      # NOTE: these are rack fqdds, so maybe we should not populate fabric info...
      fqdd.fabric.should == 'B'
      fqdd.port.should == '1'
      fqdd.partition_no.should == '1'
    end

    it 'should parse rack fqdd in port 2' do
      fqdd = ASM::NetworkConfiguration::NicInfo.new('NIC.Slot.2-2-3')
      fqdd.type.should == 'Slot'
      fqdd.card.should == '2'
      # NOTE: these are rack fqdds, so maybe we should not populate fabric info...
      fqdd.fabric.should == 'B'
      fqdd.port.should == '2'
      fqdd.partition_no.should == '3'
    end

  end

  describe 'when parsing a partitioned network config' do

    before do
      file_name = File.join(File.dirname(__FILE__), '..', '..',
                            'fixtures', 'network_configuration', 'blade_partitioned.json')
      @data = JSON.parse(File.read(file_name))
    end

    it 'should set fabric, interface, partition info on partitions' do
      net_config = ASM::NetworkConfiguration.new(@data)
      net_config.add_partition_info!
      partition_index = 0
      ('A'..'C').each_with_index do |fabric_letter, fabric_index|
        fabric = net_config.fabrics.find { |fabric| fabric.name == "Fabric #{fabric_letter}" }
        (1..2).each do |port_no|
          port = fabric.interfaces.find { |p| p.name == "Port #{port_no}" }
          (1..4).each do |partition_no|
            partition = port.partitions.find { |p| p.name == partition_no.to_s }
            if fabric_letter == 'A'
              # In sample data, Fabric A is enabled
              partition.fabric_letter.should == fabric_letter
              partition.port_no.should == port_no
              partition.partition_no.should == partition_no
              partition.partition_index.should == partition_index
              partition_index += 1
            else
              # In sample data, Fabrics B and C are not enabled
              partition.fabric_letter.should be_nil
              partition.port_no.should be_nil
              partition.partition_no.should be_nil
              partition.partition_index.should be_nil
            end
          end
        end
      end
    end

    it 'should populate blade nic data' do
      fqdd_to_mac = {'NIC.Integrated.1-1-1' => '00:0E:1E:0D:8C:30',
                     'NIC.Integrated.1-1-2' => '00:0E:1E:0D:8C:32',
                     'NIC.Integrated.1-1-3' => '00:0E:1E:0D:8C:34',
                     'NIC.Integrated.1-1-4' => '00:0E:1E:0D:8C:36',
                     'NIC.Integrated.1-2-1' => '00:0E:1E:0D:8C:31',
                     'NIC.Integrated.1-2-2' => '00:0E:1E:0D:8C:33',
                     'NIC.Integrated.1-2-3' => '00:0E:1E:0D:8C:35',
                     'NIC.Integrated.1-2-4' => '00:0E:1E:0D:8C:37',
      }
      ASM::WsMan.stubs(:get_mac_addresses).returns(fqdd_to_mac)
      net_config = ASM::NetworkConfiguration.new(@data)
      net_config.add_nics!(Hashie::Mash.new(:host => '127.0.0.1'))
      fabric = net_config.fabrics.find { |fabric| fabric.name == 'Fabric A' }

      # Verify all Fabric A partitions set correctly
      (1..2).each do |port_no|
        port = fabric.interfaces.find { |p| p.name == "Port #{port_no}" }
        (1..4).each do |partition_no|
          fqdd = "NIC.Integrated.1-#{port_no}-#{partition_no}"
          partition = port.partitions.find { |p| p.name == partition_no.to_s }
          partition.fqdd.should == fqdd
          partition.mac_address.should == fqdd_to_mac[fqdd]
        end
      end

      # Verify nothing set for fabric b or c
      ('B'..'C').each do |fabric_letter|
        fabric = net_config.fabrics.find { |fabric| fabric.name == "Fabric #{fabric_letter}" }
        (1..2).each do |port_no|
          port = fabric.interfaces.find { |p| p.name == "Port #{port_no}" }
          (1..4).each do |partition_no|
            partition = port.partitions.find { |p| p.name == partition_no.to_s }
            partition.fqdd.should be_nil
            partition.mac_address.should be_nil
          end
        end
      end
    end

    it 'should fail if interface not found' do
      ASM::WsMan.stubs(:get_mac_addresses).returns([])
      net_config = ASM::NetworkConfiguration.new(@data)
      endpoint = Hashie::Mash.new
      endpoint.host = '127.0.0.1'
      expect do
        net_config.add_nics!(endpoint)
      end.to raise_error(Exception)
    end

    it 'should be able to generate missing partitions' do
      fqdd_to_mac = {'NIC.Integrated.1-1-1' => '00:0E:1E:0D:8C:30',
                     'NIC.Integrated.1-2-1' => '00:0E:1E:0D:8C:31',
      }
      ASM::WsMan.stubs(:get_mac_addresses).returns(fqdd_to_mac)
      net_config = ASM::NetworkConfiguration.new(@data)
      net_config.add_nics!(Hashie::Mash.new(:host => '127.0.0.1'), :add_partitions => true)
      fabric = net_config.cards.find { |fabric| fabric.name == 'Fabric A' }

      # Verify all Fabric A partitions set correctly
      (1..2).each do |port_no|
        port = fabric.interfaces.find { |p| p.name == "Port #{port_no}" }
        (1..4).each do |partition_no|
          fqdd = "NIC.Integrated.1-#{port_no}-#{partition_no}"
          puts "====> Checking #{fqdd}"
          partition = port.partitions.find { |p| p.name == partition_no.to_s }
          partition.fqdd.should == fqdd
          if partition_no == 1
            partition.mac_address.should == fqdd_to_mac[fqdd]
          else
            partition.mac_address.should be_nil
          end
        end
      end
    end

    it 'should find PXE networks' do
      partitions = ASM::NetworkConfiguration.new(@data).get_partitions('PXE')
      partitions.size.should == 2
      partitions[0].name.should == '1'
      partitions[1].name.should == '1'
    end

    it 'should find multiple network types' do
      partitions = ASM::NetworkConfiguration.new(@data).get_partitions('PUBLIC_LAN', 'PRIVATE_LAN')
      partitions.size.should == 2
      partitions[0].name.should == '3'
      partitions[1].name.should == '3'
    end

    it 'should find single networks' do
      networks = ASM::NetworkConfiguration.new(@data).get_networks('HYPERVISOR_MANAGEMENT')
      networks.size.should == 1
      network = networks[0]
      network.name.should == 'Hypervisor Management'
      network.staticNetworkConfiguration.ipAddress.should == '172.28.12.118'
    end

    it 'should not find missing networks' do
      networks = ASM::NetworkConfiguration.new(@data).get_networks('FILESHARE')
      networks.size.should == 0
    end

    it 'should find multiple networks' do
      networks = ASM::NetworkConfiguration.new(@data).get_networks('PXE', 'HYPERVISOR_MANAGEMENT')
      networks.size.should == 2
    end

    it 'should find single network type' do
      network = ASM::NetworkConfiguration.new(@data).get_network('HYPERVISOR_MANAGEMENT')
      network.name.should == 'Hypervisor Management'
      network.staticNetworkConfiguration.ipAddress.should == '172.28.12.118'
    end

    it 'should fail to find single network if multiple management networks found' do
      network_config = ASM::NetworkConfiguration.new(@data)
      orig = network_config.get_network('HYPERVISOR_MANAGEMENT')
      dup = Hashie::Mash.new(orig)
      dup.staticNetworkConfiguration.ipAddress = '172.28.12.119'
      network_config.cards[0].interfaces[0].partitions[2].networkObjects.push(dup)
      expect do
        network = network_config.get_network('HYPERVISOR_MANAGEMENT')
      end.to raise_error(Exception)
    end

    it 'should fail to find single network if multiple management networks found' do
      expect do
        network = ASM::NetworkConfiguration.new(@data).get_network('STORAGE_ISCSI_SAN')
      end.to raise_error(Exception)
    end

    it 'should find storage networks with correct mac addresses' do
      fqdd_to_mac = {'NIC.Integrated.1-1-1' => '00:0E:1E:0D:8C:30',
                     'NIC.Integrated.1-1-2' => '00:0E:1E:0D:8C:32',
                     'NIC.Integrated.1-1-3' => '00:0E:1E:0D:8C:34',
                     'NIC.Integrated.1-1-4' => '00:0E:1E:0D:8C:36',
                     'NIC.Integrated.1-2-1' => '00:0E:1E:0D:8C:31',
                     'NIC.Integrated.1-2-2' => '00:0E:1E:0D:8C:33',
                     'NIC.Integrated.1-2-3' => '00:0E:1E:0D:8C:35',
                     'NIC.Integrated.1-2-4' => '00:0E:1E:0D:8C:37',
      }
      ASM::WsMan.stubs(:get_mac_addresses).returns(fqdd_to_mac)
      net_config = ASM::NetworkConfiguration.new(@data)
      net_config.add_nics!(Hashie::Mash.new(:host => '127.0.0.1'))
      partitions = net_config.get_partitions('STORAGE_ISCSI_SAN')
      partitions.size.should == 2
      partitions[0].name.should == '4'
      partitions[0].fqdd.should == 'NIC.Integrated.1-1-4'
      partitions[0].mac_address.should == '00:0E:1E:0D:8C:36'
      partitions[1].name.should == '4'
      partitions[1].fqdd.should == 'NIC.Integrated.1-2-4'
      partitions[1].mac_address.should == '00:0E:1E:0D:8C:37'
    end

    it 'should find single network ip addresses' do
      ips = ASM::NetworkConfiguration.new(@data).get_static_ips('HYPERVISOR_MANAGEMENT')
      ips.should == ['172.28.12.118']
    end

    it 'should find multiple static ips of same type' do
      ips = ASM::NetworkConfiguration.new(@data).get_static_ips('STORAGE_ISCSI_SAN')
      ips.sort.should == ['172.16.12.120', '172.16.12.121']
    end

    it 'should find multiple static ips with different types' do
      config = ASM::NetworkConfiguration.new(@data)
      ips = config.get_static_ips('HYPERVISOR_MANAGEMENT', 'STORAGE_ISCSI_SAN')
      ips.sort.should == ['172.16.12.120', '172.16.12.121', '172.28.12.118']
    end

    it 'should ignore dhcp when finding static ips' do
      ips = ASM::NetworkConfiguration.new(@data).get_static_ips('PXE')
      ips.empty?.should == true
    end

  end

  describe 'when parsing an un-partitioned network config' do

    before do
      file_name = File.join(File.dirname(__FILE__), '..', '..',
                            'fixtures', 'network_configuration', 'blade_unpartitioned.json')
      @data = JSON.parse(File.read(file_name))
    end

    it 'should only populate partition 1' do
      fqdd_to_mac = {'NIC.Integrated.1-1-1' => '00:0E:1E:0D:8C:30',
                     'NIC.Integrated.1-2-1' => '00:0E:1E:0D:8C:31',
                     'NIC.Mezzanine.2B-1-1' => '00:0F:1E:0D:8C:30',
                     'NIC.Mezzanine.2B-2-1' => '00:0F:1E:0D:8C:31',
                     'NIC.Mezzanine.3C-1-1' => '00:0D:1E:0D:8C:30',
                     'NIC.Mezzanine.3C-2-1' => '00:0D:1E:0D:8C:31',
      }
      ASM::WsMan.stubs(:get_mac_addresses).returns(fqdd_to_mac)
      net_config = ASM::NetworkConfiguration.new(@data)
      net_config.add_nics!(Hashie::Mash.new({:host => '127.0.0.1'}))

      # Verify all partition 1 set correctly
      ('A'..'C').each_with_index do |fabric_letter, fabric_index|
        fabric = net_config.fabrics.find { |fabric| fabric.name == "Fabric #{fabric_letter}" }
        (1..2).each do |port_no|
          port = fabric.interfaces.find { |p| p.name == "Port #{port_no}" }
          (1..4).each do |partition_no|
            partition = port.partitions.find { |p| p.name == partition_no.to_s }
            if partition_no == 1
              fqdd = if fabric_letter == 'A'
                       "NIC.Integrated.1-#{port_no}-#{partition_no}"
                     else
                       "NIC.Mezzanine.#{fabric_index + 1}#{fabric_letter}-#{port_no}-#{partition_no}"
                     end
              partition.fqdd.should == fqdd
              partition.mac_address.should == fqdd_to_mac[fqdd]
            else
              partition.fqdd.should be_nil
              partition.mac_address.should be_nil
            end
          end
        end
      end
    end
  end

  describe 'when parsing a partitioned rack network config' do

    before do
      file_name = File.join(File.dirname(__FILE__), '..', '..',
                            'fixtures', 'network_configuration', 'rack_partitioned.json')
      @data = JSON.parse(File.read(file_name))
    end

    it 'should match first card to first interface' do
      fqdd_to_mac = {'NIC.Slot.2-1-1' => '00:0A:F7:06:88:50',
                     'NIC.Slot.2-1-2' => '00:0A:F7:06:88:54',
                     'NIC.Slot.2-1-3' => '00:0A:F7:06:88:58',
                     'NIC.Slot.2-1-4' => '00:0A:F7:06:88:5C',
                     'NIC.Slot.2-2-1' => '00:0A:F7:06:88:52',
                     'NIC.Slot.2-2-2' => '00:0A:F7:06:88:56',
                     'NIC.Slot.2-2-3' => '00:0A:F7:06:88:5A',
                     'NIC.Slot.2-2-4' => '00:0A:F7:06:88:5E'}

      ASM::WsMan.stubs(:get_mac_addresses).returns(fqdd_to_mac)
      net_config = ASM::NetworkConfiguration.new(@data)
      net_config.add_nics!(Hashie::Mash.new({:host => '127.0.0.1'}))

      # Verify
      slot1 = net_config.interfaces[0]
      (1..2).each do |port_no|
        port = slot1.interfaces.find { |p| p.name == "Port #{port_no}" }
        (1..4).each do |partition_no|
          fqdd = "NIC.Slot.2-#{port_no}-#{partition_no}"
          partition = port.partitions.find { |p| p.name == partition_no.to_s }
          partition.fqdd.should == fqdd
          partition.mac_address.should == fqdd_to_mac[fqdd]
        end
      end
    end
  end

  describe 'when parsing an un-partitioned rack network config' do

    before do
      file_name = File.join(File.dirname(__FILE__), '..', '..',
                            'fixtures', 'network_configuration', 'rack_unpartitioned.json')
      @data = JSON.parse(File.read(file_name))
    end

    it 'should match first cards to first interfaces' do
      fqdd_to_mac = {'NIC.Slot.5-1-1' => '00:0A:F7:06:88:50',
                     'NIC.Slot.5-1-2' => '00:0A:F7:06:88:54',
                     'NIC.Slot.5-1-3' => '00:0A:F7:06:88:58',
                     'NIC.Slot.5-1-4' => '00:0A:F7:06:88:5C',
                     'NIC.Slot.5-2-1' => '00:0A:F7:06:88:52',
                     'NIC.Slot.5-2-2' => '00:0A:F7:06:88:56',
                     'NIC.Slot.5-2-3' => '00:0A:F7:06:88:5A',
                     'NIC.Slot.5-2-4' => '00:0A:F7:06:88:5E',
                     'NIC.Slot.3-1-1' => '01:0A:F7:06:88:50',
                     'NIC.Slot.3-1-2' => '01:0A:F7:06:88:54',
                     'NIC.Slot.3-1-3' => '01:0A:F7:06:88:58',
                     'NIC.Slot.3-1-4' => '01:0A:F7:06:88:5C',
                     'NIC.Slot.3-2-1' => '01:0A:F7:06:88:52',
                     'NIC.Slot.3-2-2' => '01:0A:F7:06:88:56',
                     'NIC.Slot.3-2-3' => '01:0A:F7:06:88:5A',
                     'NIC.Slot.3-2-4' => '01:0A:F7:06:88:5E',
                     'NIC.Slot.1-1-1' => '02:0A:F7:06:88:50',
                     'NIC.Slot.1-1-2' => '02:0A:F7:06:88:54',
                     'NIC.Slot.1-1-3' => '02:0A:F7:06:88:58',
                     'NIC.Slot.1-1-4' => '02:0A:F7:06:88:5C',
                     'NIC.Slot.1-2-1' => '02:0A:F7:06:88:52',
                     'NIC.Slot.1-2-2' => '02:0A:F7:06:88:56',
                     'NIC.Slot.1-2-3' => '02:0A:F7:06:88:5A',
                     'NIC.Slot.1-2-4' => '02:0A:F7:06:88:5E',
                     'NIC.Slot.7-1-1' => '03:0A:F7:06:88:50',
                     'NIC.Slot.7-1-2' => '03:0A:F7:06:88:54',
                     'NIC.Slot.7-1-3' => '03:0A:F7:06:88:58',
                     'NIC.Slot.7-1-4' => '03:0A:F7:06:88:5C',
                     'NIC.Slot.7-2-1' => '03:0A:F7:06:88:52',
                     'NIC.Slot.7-2-2' => '03:0A:F7:06:88:56',
                     'NIC.Slot.7-2-3' => '03:0A:F7:06:88:5A',
                     'NIC.Slot.7-2-4' => '03:0A:F7:06:88:5E'}

      ASM::WsMan.stubs(:get_mac_addresses).returns(fqdd_to_mac)
      net_config = ASM::NetworkConfiguration.new(@data)
      net_config.add_nics!(Hashie::Mash.new({:host => '127.0.0.1'}))

      # Verify 3 cards, unpartitioned
      to_slots = {0 => 1, 1 => 3, 2 => 5, 3 => 7}
      found_macs = []
      (0..3).each do |card_index|
        card = net_config.cards.find { |c| c.card_index == card_index }
        slot = to_slots[card_index]
        (1..2).each do |port_no|
          port = card.interfaces.find { |p| p.name == "Port #{port_no}" }
          (1..4).each do |partition_no|
            fqdd = "NIC.Slot.#{slot}-#{port_no}-#{partition_no}"
            partition = port.partitions.find { |p| p.name == partition_no.to_s }
            if partition_no > 1
              partition.should be_nil
            else
              partition.fqdd.should == fqdd
              mac = fqdd_to_mac[fqdd]
              partition.mac_address.should == mac
              found_macs.include?(mac).should be_false
              found_macs.push(mac)
            end
          end
        end
      end
    end
  end

end
