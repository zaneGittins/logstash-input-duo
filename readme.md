# Logstash DUO Plugin

This Logstash input plugin ingests events from DUO using the admin APIs. It ingests the following events:

* Authentication logs
* Administrator logs
* Telephony logs
* Offline enrollment logs
* Trust monitor logs

## Install

```bash
# Git clone and build gem, alternatively, download the latest gem from the repo.
git clone https://github.com/zaneGittins/logstash-input-duo
cd logstash-input-duo
gem build logstash-input-duo.gemspec

# Install the plugin
sudo /usr/share/logstash/bin/logstash-plugin install ~/logstash-input-duo/logstash-input-duo-1.0.1.gem
```

## Remove

```bash
sudo /usr/share/logstash/bin/logstash-plugin remove logstash-input-duo
```

## Configure

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
