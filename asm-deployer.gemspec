Gem::Specification.new do |s|
  s.name        = 'asm-deployer'
  s.version     = '0.0.1'
  s.licenses    = ['Dell 2014']
  s.summary     = 'Dell ASM Deployer'
  s.description = 'Dell ASM Deployer'
  s.authors     = ['Dell']
  s.email       = 'asm@dell.com'
  s.homepage    = 'https://github.com/dell-asm/asm-deployer'

  s.add_dependency('crack')
  s.add_dependency('rest-client')
  s.add_dependency('securerandom')
  s.add_dependency('sequel')
  s.add_dependency('sinatra')

  s.files        = Dir.glob("lib/**/*")
  s.require_path = 'lib'
end
