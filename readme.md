# Logstash DUO Trustmonitor Plugin

LogStash input for DUO Trust Monitor.

## Installation

```bash
cd /opt
git clone https://github.com/zaneGittins/logstash-input-cisco_amp
cd logstash-input-cisco_amp
gem build logstash-input-cisco_amp.gemspec
cd /usr/share/logstash
./bin/logstash-plugin install /opt/logstash-input-duo_trustmonitor/logstash-input-duo_trustmonitor-1.0.0.gem
```

## Configuration

* ikey = integration key.
* skey = secret key.
* host = DUO admin API fqdn.
* interval = time in minutes to wait between polling the API for new Trust Monitor events.

```
input {
  logstash-input-duo_trustmonitor {
    ikey => "<Your Admin DUO Integration Key.>"
    skey => "<Your Admin DUO Secret Key.>"
    host => "<Your Admin DUO host.>"
    interval => 1
  }
}
output {
    stdout { codec => rubydebug }
}
```

## References

* https://github.com/duosecurity/duo_api_ruby