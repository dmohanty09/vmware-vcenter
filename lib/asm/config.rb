require 'hashie'

module ASM
  class Config
    def initialize(config_file = nil)
      config_file ||= ENV["ASM_CONFIG"] ||
          File::join(File::dirname(__FILE__), '..', '..', 'config.yaml')
      yaml = YAML.load_file(config_file)
      @mash = Hashie::Mash.new(yaml)
    end

    # Forward methods we don't define directly to the mash
    def method_missing(sym, *args, &block)
      @mash.send(sym, *args, &block)
    end

  end
end