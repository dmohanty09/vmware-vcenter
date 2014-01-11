require 'sinatra'
require 'json'
require 'puppet'
require 'logger'
require 'asm'
require 'asm/service_deployment'

class ASM::App < Sinatra::Base

  configure do
    set :bind, '0.0.0.0'
    # only allow a single request to be processed at a time
    set :lock, true
  end

  # TODO make sure that only one of these can be done at a time
  post '/process_service_profile' do
    data = JSON.parse(request.body.read)
    ASM.process_deployment(data)
  end

  get '/logs/:name' do | name |
    name
  end

end
