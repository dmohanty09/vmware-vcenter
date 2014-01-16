require 'sinatra'
require 'json'
require 'logger'
require 'asm'
require 'asm/service_deployment'

class ASM::App < Sinatra::Base

  configure do
    set :bind, '0.0.0.0'
    # only allow a single request to be processed at a time
    set :lock, true
    ASM.init
  end

  # Execute deployment
  post '/process_service_profile' do
    ASM.process_deployment_request(request)
  end

  # Write deployment files and info, but skip running puppet
  post '/debug_service_profile' do
    ASM.debug_deployment_request(request)
  end

  # Retrieve logs for a deployment id
  get '/logs/:id' do | id |
    content_type :json
    logs = []
    log_file = File.join(ASM.base_dir, id.to_s, 'deployment.log')
    File.open(log_file, 'r').each_line do |line|
      if line =~ /^\w, \[(.*?)\]  \w+ -- : (.*)/
        logs.push({'msg' => $2, 'datetime' => $1})
      else
        ASM.logger.warn("Unexpected log line: #{line}")
      end
    end
    logs.to_json
  end

end
