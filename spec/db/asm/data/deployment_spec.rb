require 'spec_helper'
require 'sequel'
require 'asm/config'
require 'asm/data/deployment'

describe ASM::Data::Deployment do

  before do
    config = ASM::Config.new(ASM.test_config_file)
    @database = Sequel.connect(config.database_url)
    @test_guid = "test-guid-#{Time.new.to_i}"
    @data = ASM::Data::Deployment.new(@database)
    @data.create(@test_guid, 'Test Deployment 1')

    path = File.join(File.dirname(__FILE__), '..', '..', '..', '..', 'spec',
                     'fixtures', 'deployments',
                     'ff808081452c813b01453c4b14e80751', 'deployment.json')
    @deployment_data = JSON.parse(File.read(path))
  end

  after do
    @data.delete
    @database.disconnect
  end

  describe 'crud tests' do

    it 'should create deployment' do
      @data.id.should > 0
    end

    it 'should not create duplicate deployments' do
      expect do
        @data.create(@test_guid, 'Test Deployment 1')
      end.to raise_error(Sequel::UniqueConstraintViolation)
      @data.delete
    end

    it 'should find a deployment' do
      data = ASM::Data::Deployment.new(@database)
      data.load(@test_guid)
      data.id.should == @data.id
      data.delete
    end

    it 'should create an execution' do
      @data.create_execution(@deployment_data)
      @data.execution_id.should_not be_nil
    end

    it 'should delete a deployment' do
      @data.delete
      expect do
        @data.load(@test_guid)
      end.to raise_error(ASM::Data::NotFoundException)
    end

  end

  describe 'update status tests' do
    before do
      @data.create_execution(@deployment_data)
    end

    it 'should update the status' do
      @data.set_status('in_progress')
      execution = @data.get_execution
      execution.status.should == 'in_progress'
      execution.end_time.should be_nil
    end

    it 'should reject invalid status' do
      expect do
        @data.set_status('foo')
      end.to raise_error(ASM::Data::InvalidStatus)
    end

    it 'should set end_time on error' do
      @data.set_status('error')
      execution = @data.get_execution
      # execution.status.should == 'error'
      execution.end_time.should_not be_nil
    end

    it 'should set end_time on complete' do
      @data.set_status('complete')
      execution = @data.get_execution
      execution.status.should == 'complete'
      execution.end_time.should_not be_nil
    end

  end

  describe 'update component status tests' do

    before do
      @data.create_execution(@deployment_data)
      @execution = @data.get_execution
    end

    it 'should update the status' do
      component = @execution.components.first
      @data.set_component_status(component.id, 'in_progress')
      execution = @data.get_execution
      component2 = execution.components.first
      component2.id.should == component.id
      component2.status.should == 'in_progress'
      component2.end_time.should be_nil
    end

    it 'should reject invalid status' do
      component = @execution.components.first
      expect do
        @data.set_component_status(component.id, 'foo')
      end.to raise_error(ASM::Data::InvalidStatus)
    end

    it 'should set end_time on error' do
      component = @execution.components.first
      @data.set_component_status(component.id, 'error')
      execution = @data.get_execution
      component2 = execution.components.first
      component2.id.should == component.id
      component2.status.should == 'error'
      component2.end_time.should_not be_nil
    end

    it 'should set end_time on complete' do
      component = @execution.components.first
      @data.set_component_status(component.id, 'complete')
      execution = @data.get_execution
      component2 = execution.components.first
      component2.id.should == component.id
      component2.status.should == 'complete'
      component2.end_time.should_not be_nil
    end

    it 'should fail to find non-existent executions' do
      expect do
        @data.get_execution(1)
      end.to raise_error(ASM::Data::NotFoundException)
    end

    it 'should rotate executions when new ones are created' do
      orig_status = @execution.status
      @data.create_execution(@deployment_data)
      @data.set_status(:complete)
      @data.get_execution.status.should == 'complete'
      @data.get_execution(1).status.should == orig_status
    end

  end

  describe 'logging tests' do

    before do
      @data.create_execution(@deployment_data)
      @execution = @data.get_execution
    end

    it 'should log a message and update status' do
      @data.log(:info, 'Test message')
      @data.get_execution.message.should == 'Test message'
      @data.get_logs.last.message.should == 'Test message'
    end

    it 'should reject an invalid log level' do
      expect do
        @data.log('bird', 'Test message')
      end.to raise_error(ASM::Data::InvalidLogLevel)
    end

    it 'should log a component message and update its status' do
      comp = @execution.components.last
      @data.log(:info, 'Component test message', :component_id => comp.id)
      @data.get_execution.message.should be_nil
      @data.get_logs.last.message.should == 'Component test message'
    end

  end

  describe 'mark in-progress as failed' do
    it 'should mark one execution as failed' do
      @data.create_execution(@deployment_data)
      @data.log(:info, 'Test message')
      # deployment should be in_progress
      ASM::Data::Deployment.mark_in_progress_failed(@database)
      @data.get_execution.status.should == 'error'
      # message should be overwritten with a "deployment failed message"
      @data.get_execution.message.should_not == 'Test message'
    end

    it 'should mark two executions as failed' do
      @data.create_execution(@deployment_data)
      @data.create_execution(@deployment_data)
      # deployment should be in_progress
      ASM::Data::Deployment.mark_in_progress_failed(@database)
      @data.get_execution.status.should == 'error'
      @data.get_execution.message.should_not be_nil
      @data.get_execution(1).status.should == 'error'
      @data.get_execution(1).message.should_not be_nil
    end

    it 'should not mark completed executions as failed' do
      @data.create_execution(@deployment_data)
      @data.log(:info, 'Test message')
      @data.set_status('complete')
      ASM::Data::Deployment.mark_in_progress_failed(@database)
      @data.get_execution.status.should == 'complete'
      @data.get_execution.message.should == 'Test message'
    end

  end

  describe 'redeployment tests' do
    before do
      @data.create_execution(@deployment_data)
      @execution = @data.get_execution
    end

    it 'should create new components' do
      orig = @execution.components.first
      orig.should_not be_nil
      @data.set_component_status(orig.id, 'complete')
      e1 = @data.get_execution(0)
      new = e1.components.first
      new.id.should == orig.id
      new.status.should == 'complete'

      # create 2nd execution
      @data.create_execution(@deployment_data)

      # Verify the old execution hasn't changed
      e1 = @data.get_execution(1)
      new = e1.components.first
      new.id.should == orig.id
      new.status.should == 'complete'
    end

    it 'should retain previous execution statuses' do
      orig = @execution.components.first
      orig.id.should_not be_nil
      @data.set_component_status(orig.id, 'complete')

      # create 2nd execution
      @data.create_execution(@deployment_data)

      # Verify the old execution hasn't changed
      new = @data.get_execution.components.first
      new.id.should == orig.id
      new.status.should == 'complete'

      # Reset to in_progress
      @data.set_component_status(orig.id, 'in_progress')

      # create 3nd execution
      @data.create_execution(@deployment_data)

      # Verify the old execution hasn't changed
      new = @data.get_execution.components.first
      new.id.should == orig.id
      new.status.should == 'in_progress'

    end

  end

end
