source 'https://rubygems.org'

gem 'aescrypt'
gem 'crack'
gem 'hashie'
# WARNING: Failing to specify the 9.2.1002.1 version of jdbc-postgres results
# in failure to load the postgresql jar on torquebox, not sure why
gem 'jdbc-postgres', '~> 9.2.1002.1'
gem 'rest-client'
gem 'sequel'
gem 'sinatra'

group :development, :test do
  gem 'rake'
  gem 'rspec', :require => false
  gem 'mocha', :require => false
  gem 'puppet', :require => false
  gem 'puppetlabs_spec_helper', :require => false
end
