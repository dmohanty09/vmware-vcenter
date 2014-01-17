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
    logs = ASM::Util.get_logs(id)
    logs.to_json
  end

  get '/status/:id' do |id|
    content_type :json
    ASM::Util.get_status(id).to_json
  end

end
