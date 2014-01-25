#!/usr/bin/env ruby

require 'set'

class GetWWPN
    def initialize (ipaddress, username, password)
        @ipaddress = ipaddress
        @username = username
        @password = password
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
