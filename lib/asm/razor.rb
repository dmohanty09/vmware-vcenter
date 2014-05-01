require 'rest_client'

module ASM
  class Razor

    RAZOR_API_URL = 'http://localhost:8081/api'

    def initialize(razor_api_url = RAZOR_API_URL)
      @api_url = razor_api_url
    end

    def get(type, name=nil)
      begin
        response = nil
        url = [@api_url, type, name].compact.join('/')
        response = RestClient.get(url)
      rescue RestClient::ResourceNotFound => e
        raise(CommandException, "Rest call to #{url} failed: #{e}")
      end
      if response.code == 200
        result = JSON.parse(response)
        result.include?('items') ? result['items'] : result
      else
        raise(CommandException, "Bad http code: #{response.code}:\n#{response.to_str}")
      end
    end

    def find_node(serial_num)
      ret = nil
      results = get('nodes').each do |node|
        results = get('nodes', node['name'])
        # Facts will be empty for a period until server checks in
        serial = (results['facts'] || {})['serialnumber']
        if serial == serial_num
          ret = results
        end
      end
      ret
    end

    def find_host_ip(serial_num)
      node = find_node(serial_num)
      if node && node['facts'] && node['facts']['ipaddress']
        node['facts']['ipaddress']
      else
        nil
      end
    end

    def find_host_ip_blocking(serial_num, timeout)
      ipaddress = nil
      max_sleep = 30
      ASM::Util.block_and_retry_until_ready(timeout, CommandException, max_sleep) do
        ipaddress = find_host_ip(serial_num)
        unless ipaddress
          raise(CommandException, "Did not find our node by its serial number. Will try again")
        end
      end
      ipaddress
    end


  end
end
