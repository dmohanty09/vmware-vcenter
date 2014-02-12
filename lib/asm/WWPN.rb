#
# This class is used to get wwpns from Dell servers
#
class ASM::WWPN

  def self.get(ipaddress, username, password)
    # TODO do we need to specify this external link?
    # it makes it seem this has an external dependency
    # on network connectivity which we know is not
    # true
    wsmanCmdResponse = `wsman enumerate http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/root/DCIM/DCIM_FCView  -h "#{ipaddress}" -V -v -c dummy.cert -P 443 -u "#{username}" -p "#{password}" -j utf-8 -y basic`
    wsmanCmdResponse.split(/\n/).collect do |ele|
      if ele =~ /<n1:VirtualWWPN>(\S+)<\/n1:VirtualWWPN>/
        $1
      end
    end
  end

end
