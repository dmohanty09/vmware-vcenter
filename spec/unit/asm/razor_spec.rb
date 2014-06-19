require 'spec_helper'
require 'asm/razor'
require 'json'

describe ASM::Razor do

  def mock_response(code, data)
    response = mock('response')
    response.stubs(:code).returns(code)
    json = JSON.generate(data)
    response.stubs(:to_s).returns(json)
    response.stubs(:to_str).returns(json)
    response
  end

  describe 'razor find_node' do

    def build_node_data(name, serial_number, facts = {})
      facts['serial_number'] = serial_number
      {'name' => name,
       'hw_info' => {'serial' => serial_number.downcase},
       'facts' => facts}
    end

    before do
      @node_name = 'node1'
      fake_api_url = 'http://foo/bar'
      @nodes_url = "#{fake_api_url}/collections/nodes"
      @razor = ASM::Razor.new(:api_url => fake_api_url)
      @nodes = {'items' => [{'name' => 'node1'}, {'name' => 'node2'}]}
      RestClient.stubs(:get).with(@nodes_url).
          returns(mock_response(200, @nodes))

      @node1 = build_node_data('node1', 'NODE_1_SERIAL_NUMBER')
      RestClient.stubs(:get).with("#{@nodes_url}/node1").
          returns(mock_response(200, @node1))

      @node2 = build_node_data('node2', 'NODE_2_SERIAL_NUMBER',
                               {'ipaddress' => '192.168.1.100'})
      RestClient.stubs(:get).with("#{@nodes_url}/node2").
          returns(mock_response(200, @node2))

      RestClient.stubs(:get).with("#{@nodes_url}/bad_node").
          returns(mock_response(404, {:msg => 'No such node'}))
    end

    describe 'when node not found' do

      it 'get should raise CommandException' do
        expect do
          @razor.get('nodes', 'bad_node')
        end.to raise_error(ASM::CommandException)
      end

      it 'should return nil' do
        @razor.find_node('NO_SUCH_SERIAL_NUMBER').should == nil
      end

      it 'should not return ip' do
        @razor.find_host_ip('NO_SUCH_SERIAL_NUMBER').should == nil
      end
    end

    describe 'when node found' do

      it 'get should return node' do
        @razor.get('nodes', 'node2').should == @node2
      end

      it 'should return node' do
        @razor.find_node('NODE_2_SERIAL_NUMBER').should == @node2
      end

      it 'fail if multiple node matches found' do
        node3 = build_node_data('node3', 'NODE_2_SERIAL_NUMBER',
                                {'ipaddress' => '192.168.1.101'})
        RestClient.stubs(:get).with("#{@nodes_url}/node3").
            returns(mock_response(200, node3))

        @nodes = {'items' => [{'name' => 'node1'}, {'name' => 'node2'}, {'name' => 'node3'}]}
        RestClient.stubs(:get).with(@nodes_url).
            returns(mock_response(200, @nodes))

        expect do
          @razor.find_node('NODE_2_SERIAL_NUMBER').should == @node2
        end.to raise_exception
      end

      it 'should return ip' do
        @razor.find_host_ip('NODE_2_SERIAL_NUMBER').should == '192.168.1.100'
      end
    end

  end

  describe 'razor install_status' do

    before do
      @logs = JSON.parse(File.read(File.join(File.dirname(__FILE__), '..', '..',
                                             'fixtures', 'razor_node_log.json')))
      @node_name = 'node1'
      @policy_name = 'policy-gsesx2-ff80808145a8f7d40145a8fc36630004'
      fake_api_url = 'http://foo/bar'
      @node_url = "#{fake_api_url}/collections/nodes/#{@node_name}/log"
      @razor = ASM::Razor.new(:api_url => fake_api_url)
    end

    describe 'when no logs exist' do
      it 'should return nil' do
        @logs['items'] = []
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name).should == nil
      end
    end

    describe 'when a microkernel boot event exists' do
      it 'should return :microkernel' do
        @logs['items'] = @logs['items'].slice(0, 1)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :microkernel
      end
    end

    describe 'when only bind events exist' do
      it 'should return :bind' do
        @logs['items'] = @logs['items'].slice(0, 2)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :bind
      end
    end

    describe 'when reboot event exists' do
      it 'should return :reboot' do
        @logs['items'] = @logs['items'].slice(0, 3)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :reboot
      end
    end

    describe 'when boot_install event exists' do
      it 'should return :boot_install' do
        @logs['items'] = @logs['items'].slice(0, 4)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :boot_install
      end
    end

    describe 'when boot_wim event exists' do
      it 'should return :boot_install' do
        @logs['items'] = @logs['items'].slice(0, 4)

        # Doctor up boot_install entry to look like boot_wim (seen with Windows)
        @logs['items'][3]['template'] = 'boot_wim'

        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :boot_install
      end
    end

    describe 'when most recent interesting event is boot_install' do
      it 'should return :boot_install' do
        @logs['items'] = @logs['items'].slice(0, 7)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :boot_install
      end
    end

    describe 'when boot_local event exists' do
      it 'should return :boot_local' do
        @logs['items'] = @logs['items'].slice(0, 10)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :boot_local
      end

      it 'should return the right timestamp' do 
        @logs['items'] = @logs['items'].slice(0, 10)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:timestamp].should == Time.parse("2014-04-28T16:00:03+00:00")
      end
    end

    describe 'when boot_local event exists twice' do
      it 'should return :boot_local_2' do
        @logs['items'] = @logs['items'].slice(0, 11)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :boot_local_2
      end
    end

    describe 'when boot_local event exists thrice' do
      it 'should return :boot_local_2' do
        items = @logs['items'].slice(0, 11)
        # Last item is the 2nd boot_local log, add another copy so there are 3
        items.push(items.last)
        @logs['items'] = items
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :boot_local_2
      end
    end

    describe 'when reinstall event exists twice' do
      it 'should return nil' do
        @logs['items'] = @logs['items'].slice(0, 12)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == nil
      end
    end

    describe 'when second different install has bind event' do
      it 'should still return :bind' do
        @logs['items'] = @logs['items'] + @logs['items'].slice(0, 2)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :bind
      end
    end

    describe 'when different install has started afterward' do
      it 'should return nil' do
        unrelated_bind = [{'event' => 'bind', 'policy' => 'unrelated_policy', 'timestamp' =>'2014-04-30T15:46:33+00:00'}]
        @logs['items'] = @logs['items'] + unrelated_bind
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == nil
      end
    end

    describe 'where there was a previous install' do
      it 'should return :bind after a bind event' do
        previous_logs = [{'event' => 'bind', 'policy' => 'unrelated_policy', 'timestamp' =>'2014-04-30T15:46:33+00:00'},
                         {'event' => 'reinstall', 'policy' => 'unrelated_policy', 'timestamp' =>'2014-04-30T16:46:33+00:00'}]
        @logs['items'] = previous_logs + @logs['items'].slice(0, 2)
        RestClient.stubs(:get).with(@node_url).returns(mock_response(200, @logs))
        @razor.task_status(@node_name, @policy_name)[:status].should == :bind
      end
    end

    describe 'when comparing statuses' do

      it 'should get the right ordering' do
        @razor.cmp_status(nil, :bind).should < 0
        @razor.cmp_status(:bind, :boot_local_2).should < 0
        @razor.cmp_status(:bind, :bind).should == 0
        @razor.cmp_status(:boot_local_2, :bind).should > 0
      end

      it 'should fail with invalid status' do
        expect do
          @razor.cmp_status(:foo, :bar)
        end.to raise_error(ASM::Razor::InvalidStatusException)
      end

    end

    describe 'block_until_task_complete' do

      before do
        @razor = ASM::Razor.new
      end

      describe 'when node not found' do
        it 'should raise UserException' do
          @razor.stubs(:find_node_blocking).with('fail_serial_no', 600).returns(nil)
          expect do
            @razor.block_until_task_complete('fail_serial_no', 'policy', 'task')
          end.to raise_error(ASM::UserException)
        end
      end

      describe 'when node found' do

        it 'should fail if status does not advance' do
          ASM::Util.stubs(:block_and_retry_until_ready).returns({:status => :boot_install})
          expect do
            @razor.block_until_task_complete('serial_no', 'policy', 'task')
          end.to raise_error(ASM::UserException)
        end

        it 'should fail if getting status times out' do
          ASM::Util.stubs(:block_and_retry_until_ready).raises(Timeout::Error)
          expect do
            @razor.block_until_task_complete('serial_no', 'policy', 'task')
          end.to raise_error(Timeout::Error)
        end

        it 'should succeed when status is terminal' do
          ASM::Util.stubs(:block_and_retry_until_ready).returns({:status=>:boot_local})
          @razor.block_until_task_complete('serial_no', 'policy', 'task').
              should == {:status=>:boot_local}
        end

        it 'should wait for :boot_local_2 when task is vmware' do
          ASM::Util.stubs(:block_and_retry_until_ready).returns({:status=>:boot_local_2})
          @razor.block_until_task_complete('serial_no', 'policy', 'vmware-esxi').
              should == {:status=>:boot_local_2}
        end

        it 'should wait for :boot_local_2 when task is windows' do
          ASM::Util.stubs(:block_and_retry_until_ready).returns({:status=>:boot_local_2})
          @razor.block_until_task_complete('serial_no', 'policy', 'windows').
              should == {:status=>:boot_local_2}
        end
      end

    end

  end
end
