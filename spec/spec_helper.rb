dir = File.expand_path(File.dirname(__FILE__))
$LOAD_PATH.unshift File.join(dir, 'lib')

# Don't want puppet getting the command line arguments for rake or autotest
ARGV.clear

require 'puppet'
require 'facter'
require 'mocha/api'
gem 'rspec', '>=2.0.0'
require 'rspec/expectations'

require 'puppetlabs_spec_helper/module_spec_helper'

module ASM

  # TODO: we should probably use config.yaml "environments" for this like razor does
  def self.test_config_file
    if RUBY_PLATFORM == 'java'
      File.join(File.dirname(__FILE__), 'jruby_config.yaml')
    else
      File.join(File.dirname(__FILE__), 'mri_config.yaml')
    end
  end

  def self.init_for_tests
    ASM.init(self.test_config_file)
  end
end

RSpec.configure do |config|
  # FIXME REVISIT - We may want to delegate to Facter like we do in
  # Puppet::PuppetSpecInitializer.initialize_via_testhelper(config) because
  # this behavior is a duplication of the spec_helper in Facter.
  config.before :each do
    # Ensure that we don't accidentally cache facts and environment between
    # test cases.  This requires each example group to explicitly load the
    # facts being exercised with something like
    # Facter.collection.loader.load(:ipaddress)
    Facter::Util::Loader.any_instance.stubs(:load_all)
    Facter.clear
    Facter.clear_messages
  end
end
