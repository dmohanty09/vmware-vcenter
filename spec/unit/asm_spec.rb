require 'spec_helper'
require 'asm'

describe ASM do

  it 'should return hard coded base dir' do
    FileUtils.expects(:mkdir_p).with('/opt/Dell/ASM/deployments').once
    ASM.base_dir.should == '/opt/Dell/ASM/deployments'
    # this is being called once to verify that mkdir_p is only
    # called once
    ASM.base_dir.should == '/opt/Dell/ASM/deployments'
  end

  describe 'when managing deployment processing' do

    before do
      mock = mock('deployment')
      mock.stub_everything
      ASM::ServiceDeployment.expects(:new).twice.returns(mock)
      @tmp_dir = Dir.mktmpdir
      @basic_data_1 = {'id' => 'foo'}
      @basic_data_2 = {'id' => 'bar'}
    end

    it 'should only manage deployment processing state one at a time' do
      # verifies that only one thread can enter the deployment
      # tracking methods at a time
      now = Time.now
      ASM.expects(:track_service_deployments_locked).with() do |id|
        sleep 1;
        true
      end.twice.returns(true)
      ASM.expects(:complete_deployment).twice
      [@basic_data_1, @basic_data_2].collect do |data|
        Thread.new do
          ASM.process_deployment(data)
        end
      end.each do |thd|
        thd.join
      end
      end_time = Time.now
      ((end_time - now) > 2).should be_true
    end

  end

  before do
    ASM.init
  end

  it 'should track service deployments' do
    ASM.track_service_deployments('one').should be_true
    ASM.track_service_deployments('one').should be_false
    ASM.track_service_deployments('two').should be_true
    ASM.complete_deployment('one')
    ASM.complete_deployment('two')
    ASM.track_service_deployments('one').should be_true
  end
  
  it 'should fail if we call ASM.init twice' do
    expect do
      ASM.init
    end.to raise_error(Exception, 'Can not initialize ASM class twice')
  end

  describe 'when hostlist is initialized/updated with hosts' do

    it 'should return [] list' do
      ASM.block_hostlist(['server1','server2']).should == []
    end

    it 'should return list of duplicate hosts' do
      ASM.block_hostlist(['host1','host2' ])
      ASM.block_hostlist(['host1','host2']).should == ['host1','host2']
    end

    it 'should return [] if hosts are blocked, unblocked and blocked again' do
      ASM.block_hostlist(['host1','host2', 'host3' ])
      ASM.unblock_hostlist(['host1','host2'])
      ASM.block_hostlist(['host1','host2']).should == []
    end
    it 'should return list of hosts if hosts are if they already exist in block list' do
      ASM.block_hostlist(['host1','host2', 'host3' ])
      ASM.unblock_hostlist(['host1','host2'])
      ASM.block_hostlist(['host3']).should == ['host3']
    end
  end
  
  after do
    # Use send to bypass private scope
    ASM.send(:clear_mutex)
  end
  
end
