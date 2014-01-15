require 'asm/util'
require 'spec_helper'
require 'tempfile'

describe AsmUtil do
  
  before do
    @tmpfile = Tempfile.new('AsmUtil_spec')
  end

  after do
    @tmpfile.unlink
  end

  describe 'when device config file is valid' do

    it 'should be able to parse single device config file' do
      certname = 'equallogic-172.17.15.10'
      text = <<END
[#{certname}]
  type equallogic
  url https://eqluser:eqlpw@172.17.15.10

END
      @tmpfile.write(text)
      @tmpfile.close

      conf = AsmUtil.parse_device_config(@tmpfile)
      conf.keys.size.should eq 1
      conf[certname].provider.should eq 'equallogic'
      conf[certname].url.should eq 'https://eqluser:eqlpw@172.17.15.10'
    end
    
  end


  # TODO: test invalid device config files

  # TODO: test idrac resource configuration
  
end
