#!/usr/bin/env ruby

require 'set'
require 'uri'
#require '/etc/puppetlabs/puppet/modules/asm_lib/lib/security/encode'

class GetWWPN
    def initialize (ipaddress, username, password)
        @ipaddress = ipaddress
        @username = username
        @password = password
	    @password = URI.decode(get_plain_password(@password))
    end
    
  def get_plain_password(encoded_password)
      plain_password=`/opt/puppet/bin/ruby /opt/asm-deployer/lib/asm/encode_asm.rb #{encoded_password}`
      plain_password=plain_password.strip
      return plain_password
    end

    def getwwpn
      wwpnumber = ""
      wsmanCmdResponse = `wsman enumerate http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/DCIM/DCIM_FCView  -h "#{@ipaddress}" -V -v -c dummy.cert -P 443 -u "#{@username}" -p "#{@password}" -j utf-8 -y basic`
      data=wsmanCmdResponse.split(/\n/)
      data.each do |ele|
        if ele.to_s =~ /<n1:VirtualWWPN>(\S+)<\/n1:VirtualWWPN>/
          vardata = $1
	  if wwpnumber.length > 0
    	    wwpnumber = wwpnumber + ",#{vardata}"
          else
            wwpnumber = vardata
          end
        end
      end
      return wwpnumber
    end

end
