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

  # Retrieve logs for a deployment id
  get '/logs/:id' do | id |
    content_type :json
    logs = ASM::Util.get_logs(id)
    logs.to_json
  end

  get '/puppetreport/:id/:certname' do |id, certname|
    content_type :json
    report = ASM::Util.get_report(id, certname)
    report.to_json
  end

  get '/puppetlog/:id/:certname' do |id, certname|
    content_type :json
    log = ASM::Util.get_puppet_log(id, certname)
    log.to_json
  end

  get '/status' do
    content_type :json
    ASM.active_deployments.to_json
  end

  get '/status/:id' do |id|
    content_type :json
    ASM::Util.get_status(id).to_json
  end

  put '/deployments/:id' do |id|
    ASM.retry_deployment(id, JSON.parse(request.body.read))
  end

  delete '/deployments/:id' do | id |
    ASM.clean_deployment(id)
  end
end
