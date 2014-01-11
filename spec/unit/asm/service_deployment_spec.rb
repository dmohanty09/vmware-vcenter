require 'asm/service_deployment'
require 'json'

describe ASM::ServiceDeployment do

  before do
    data_file = File.join(File.dirname(__FILE__), '..', '..', 'fixtures', 'current.json')
    @data = JSON.parse(File.read(data_file))
    @sd = ASM::ServiceDeployment.new(@data['id'])
  end

  it 'should process' do
    x = @sd.process(@data)
  end

end
