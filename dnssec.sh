#!/bin/bash
cd /usr/local/autodnssec && /usr/local/bin/ruby ./dnssec.rb $@ >> /var/log/dnssec.log 2>&1
