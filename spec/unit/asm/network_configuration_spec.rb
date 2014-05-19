require 'spec_helper'
require 'asm/network_configuration'

describe ASM::NetworkConfiguration do

  describe 'when parsing NIC FQDDs' do

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

  end

  describe 'when parsing a partitioned network config' do

    before do
      file_name = File.join(File.dirname(__FILE__), '..', '..',
                            'fixtures', 'network_configuration', 'partitioned.json')
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
              partition.port_no.should == port_no.to_s
              partition.partition_no.should == partition_no.to_s
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

  end

  describe 'when parsing an un-partitioned network config' do

    before do
      file_name = File.join(File.dirname(__FILE__), '..', '..',
                            'fixtures', 'network_configuration', 'unpartitioned.json')
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
      fabric = net_config.fabrics.find { |fabric| fabric.name == 'Fabric A' }

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

end
