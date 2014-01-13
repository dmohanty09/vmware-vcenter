require 'asm/service_deployment'
require 'json'
require 'spec_helper'
require 'yaml'

describe ASM::ServiceDeployment do

  before do
    @tmp_dir = Dir.mktmpdir
    data_file = File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'current.json')
    @data = JSON.parse(File.read(data_file))
    @sd = ASM::ServiceDeployment.new(@data['id'])
    ASM.stubs(:base_dir).returns(@tmp_dir)
  end

  describe 'when data is valid' do

    it 'should be able to process data for a single resource' do
      r_file = "#{@tmp_dir}/8000/resources/cert.yaml"
      ASM.expects(:run_command).with(
        "sudo puppet asm process_node --filename #{r_file} --run_type apply --always-override cert", "#{@tmp_dir}/8000/cert.out") do |cmd|
        File.open("#{@tmp_dir}/8000/cert.out", 'w') do |fh|
          fh.write('Results: For 0 resources. 0 failed. 0 updated successfully.')
        end  
      end
      @sd.process({'serviceTemplate' => {'components' => [
        {'type' => 'TEST', 'id' => 'cert', 'resources' => [
          {'id' => 'user', 'parameters' => [
            {'id' => 'title', 'value' => 'foo'},
            {'id' => 'foo', 'value' => 'bar'}
          ]}
        ]}
      ]}})
      YAML.load_file(r_file)['user']['foo']['foo'].should == 'bar'
    end

  end

  describe 'when data is invalid' do

    it 'should warn when no serviceTemplate is defined' do
      @mock_log = mock('foo')
      @sd.expects(:logger).twice.returns(@mock_log)
      @mock_log.expects(:info).with('Starting deployment ')
      @mock_log.expects(:warn).with('Service deployment data has no serviceTemplate defined')
      @sd.process({})
    end

    it 'should warn when there are no components' do
      @mock_log = mock('foo')
      @sd.expects(:logger).twice.returns(@mock_log)
      @mock_log.expects(:info).with('Starting deployment ')
      @mock_log.expects(:warn).with('service deployment data has no components')
      @sd.process({'serviceTemplate' => {}})
    end

    it 'should fail when resources do not have types' do
      expect do
        @sd.process({'serviceTemplate' => {'components' => [
          {'id' => 'cert', 'type' => 'TEST', 'resources' => [
            {}
          ]}
        ]}})
      end.to raise_error(Exception, 'resource found with no type')
    end

    it 'should fail when resources do not have paremeters' do
      expect do
        @sd.process({'serviceTemplate' => {'components' => [
          {'type' => 'TEST', 'id' => 'cert2', 'resources' => [
            {'id' => 'user'}
          ]}
        ]}})
      end.to raise_error(Exception, 'resource of type user has no parameters')
    end

    it 'should fail when component has no certname' do
      expect do
        @sd.process({'serviceTemplate' => {'components' => [
          {'type' => 'TEST', 'resources' => [
            {'id' => 'user'}
          ]}
        ]}})
      end.to raise_error(Exception, 'Component has no certname')
    end

    it 'should fail when a resource has no title' do
      expect do
        @sd.process({'serviceTemplate' => {'components' => [
          {'type' => 'TEST', 'id' => 'foo', 'id' => 'cert4', 'resources' => [
            {'id' => 'user', 'parameters' => []}
          ]}
        ]}})
      end.to raise_error(Exception, 'Resource from component type TEST has resource user with no title')
    end

  end

end
