require 'rubygems'
require 'puppetlabs_spec_helper/rake_tasks'
require 'rake'
require 'rspec/core/rake_task'

RSpec::Core::RakeTask.new(:spec)

# task :default => :spec

# To run unit tests:                 bundle exec rake spec:suite:unit
# To run database integration tests: bundle exec rake spec:suite:db

namespace :spec do
  namespace :suite do
    desc 'Run all specs in unit spec suite'
    RSpec::Core::RakeTask.new('unit') do |t|
      t.pattern = './spec/unit/**/*_spec.rb'
    end
  end

  namespace :suite do
    desc 'Run all specs in db spec suite'
    RSpec::Core::RakeTask.new('db') do |t|
      t.pattern = './spec/db/**/*_spec.rb'
    end
  end
end

# WARNING: These db tasks do not work properly. Just use the db/schema.sql file
namespace :db do
  desc 'Run database migrations'
  task :migrate do |cmd, args|
    require 'asm'
    ASM.init unless ASM.initialized?
    require 'sequel/extensions/migration'
    Sequel::Migrator.apply(ASM.database, 'db/migrate')
  end

  desc 'Rollback the database'
  task :rollback do |cmd, args|
    require 'asm'
    ASM.init unless ASM.initialized?
    require 'sequel/extensions/migration'
    version = (row = ASM.database[:schema_info].first) ? row[:version] : nil
    Sequel::Migrator.apply(ASM.database, 'db/migrate', version - 1)
  end

  desc 'Nuke the database (drop all tables)'
  task :nuke do |cmd, args|
    require 'asm'
    ASM.init unless ASM.initialized?
    ASM.database.tables.each do |table|
      ASM.database.run("DROP TABLE #{table} CASCADE")
    end
  end

  desc 'Reset the database'
  task :reset => [:nuke, :migrate]
end
