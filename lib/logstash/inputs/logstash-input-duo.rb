class LogStash::Inputs::DUO < LogStash::Inputs::Base
  config_name "logstash-input-duo"
  default :codec, "json"

  config :ikey, :validate => :string

  config :skey, :validate => :string

  config :host, :validate => :string

  config :interval, :validate => :number, :default => 1

  public
  def register
    @interval = @interval * 60
  end

  def digest(key, text)    
    OpenSSL::HMAC.hexdigest(DIGEST, key, text)
  end

  def canonicalize(method, host, path, params, options = {})
    options[:date] ||= time
    canon = [
      options[:date],
      method.upcase,
      host.downcase,
      path,
      encode_params(params)
    ]
    [options[:date], canon.join("\n")]
  end

  def encode_key_val(k, v)
    # encode the key and the value for a url
    key = ERB::Util.url_encode(k.to_s)
    value = ERB::Util.url_encode(v.to_s)
    key + '=' + value
  end

  def encode_params(params_hash = nil)
    return '' if params_hash.nil?
    params_hash.sort.map do |k, v|
      # when it is an array, we want to add that as another param
      # eg. next_offset = ['1547486297000', '5bea1c1e-612c-4f1d-b310-75fd31385b15']
      if v.is_a?(Array)
        encode_key_val(k, v[0]) + '&' + encode_key_val(k, v[1])
      else
        encode_key_val(k, v)
      end
    end.join('&')
  end

  def request_uri(path, params = nil)
    u = 'https://' + @host + path
    u += '?' + encode_params(params) unless params.nil?
    URI.parse(u)
  end

  def sign(method, host, path, params, options = {})
      date, canon = canonicalize(method, host, path, params, date: options[:date])
      [date, OpenSSL::HMAC.hexdigest('sha1', @skey, canon)]
  end

  def time
      Time.now.rfc2822
  end

  def request(method, path, params = nil)
    uri = request_uri(path, params)
    current_date, signed = sign(method, uri.host, path, params)

    request = Net::HTTP.const_get(method.capitalize).new uri.to_s
    request.basic_auth(@ikey, signed)
    request['Date'] = current_date
    request['User-Agent'] = 'duo_api_ruby/1.2.0'

    Net::HTTP.start(uri.host, uri.port, *@proxy,
                    use_ssl: true, ca_file: @ca_file,
                    verify_mode: OpenSSL::SSL::VERIFY_PEER) do |http|
      resp = http.request(request)
    end
  end

  def process_trust_events(queue, response, identifier)
    data = JSON.parse(response)
    if data.has_key?("response")
      events = data['response']
      events['events'].each do |child|
        child['product'] = identifier
        event = LogStash::Event.new("message" => child.to_json)
        decorate(event)
        queue << event
      end
    end
  end

  def process_auth_events(queue, response, identifier)
    data = JSON.parse(response)
    if data.has_key?("response")
      events = data['response']
      events['authlogs'].each do |child|
        child['product'] = identifier
        event = LogStash::Event.new("message" => child.to_json)
        decorate(event)
        queue << event
      end
    end
  end

  def process_log_events(queue, response, identifier)
    data = JSON.parse(response)
    if data.has_key?("response")
      events = data['response']
      events.each do |child|
        child['product'] = identifier
        event = LogStash::Event.new("message" => child.to_json)
        decorate(event)
        queue << event
      end
    end
  end

  def run(queue)
    while !stop?

      # Current time - interval from last poll of API.
      adjusted_time = Time.now.utc - (@interval)

      # Minimum / Maximum timestamps to search for events.
      mintime = (adjusted_time).strftime('%s%3N')
      maxtime = Time.now.utc.strftime('%s%3N')
      mintimeSeconds = (adjusted_time).strftime('%s')
      
      # DUO Trust Monitor Logs
      response = request 'GET', "/admin/v1/trust_monitor/events", {mintime: mintime, maxtime:maxtime}
      process_trust_events(queue, response.body, 'duo_trust_monitor')

      # DUO Authentication Logs
      response = request 'GET', "/admin/v2/logs/authentication", {mintime: mintime, maxtime:maxtime}
      process_auth_events(queue, response.body, 'duo_authentication')

      # DUO Administrator Logs
      response = request 'GET', "/admin/v1/logs/administrator", {mintime: mintimeSeconds}
      process_log_events(queue, response.body, 'duo_administrator')

      # DUO Telephony Logs
      response = request 'GET', "/admin/v1/logs/telephony", {mintime: mintimeSeconds}
      process_log_events(queue, response.body, 'duo_telephony')

      # DUO Offline Enrollment Logs
      response = request 'GET', "/admin/v1/logs/offline_enrollment", {mintime: mintimeSeconds}
      process_log_events(queue, response.body, 'duo_offline_enrollment')

      Stud.stoppable_sleep(@interval) { stop? }
    end # loop
  end # def run

  def stop
  end
end