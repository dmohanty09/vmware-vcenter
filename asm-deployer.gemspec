Gem::Specification.new do |s|
  s.name        = 'asm-deployer'
  s.version     = '0.0.1'
  s.licenses    = ['Dell 2014']
  s.summary     = 'Dell ASM Deployer'
  s.description = 'Dell ASM Deployer'
  s.authors     = ['Dell']
  s.email       = 'asm@dell.com'
  s.homepage    = 'https://github.com/dell-asm/asm-deployer'

  s.files        = Dir.glob("lib/**/*")
  s.require_path = 'lib'
end
