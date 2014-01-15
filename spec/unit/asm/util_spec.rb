require 'asm/util'
require 'spec_helper'
require 'tempfile'

describe ASM::Util do
  
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

      conf = ASM::Util.parse_device_config(@tmpfile)
      conf.keys.size.should eq 1
      conf[certname].provider.should eq 'equallogic'
      conf[certname].url.should eq 'https://eqluser:eqlpw@172.17.15.10'
    end
    
  end

  describe 'retries and timeouts' do

    it 'should reraise unhandled exceptions' do
      expect do
        ASM::Util.block_and_retry_until_ready(1) do
          raise(Exception)
        end
      end.to raise_error(Exception)
    end

    it 'should raise an exception on timeout' do
      expect do
        ASM::Util.block_and_retry_until_ready(1) do
          sleep 2
        end
      end.to raise_error(Timeout::Error)
    end

    it 'should forgive a single exception' do
      mock_log = mock('foo')
      ASM.expects(:logger).returns(mock_log)
      mock_log.expects(:info).with('Caught exception Exception: Exception')
      self.expects(:foo).twice.raises(Exception).then.returns('bar')
      ASM::Util.block_and_retry_until_ready(5, Exception) do
        foo
      end.should == 'bar'
    end

  end



  # TODO: test invalid device config files

  # TODO: test idrac resource configuration
  
end
