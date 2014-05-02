# SYNOPSIS

If you run a server or two, and host DNS using BIND, you may find these scripts useful in automating DNSSEC. Additionally, given a path to a certificate, autodnssec will alse generate DANE compliant TLSA records. 

This software is an adaptation of the work by Rene van Lieshout with built-in support for Plesk. 

Tested with:

* Ruby 1.9.3
* BIND 9.8.7 and 9.9.5

# INSTALLATION

	cd /usr/local && git clone https://github.com/TamerRizk/autodnssec.git

# CONFIGURATION

In dnssec.rb:

	BIND_PATH = "/var/named/chroot"
	ZONE_PATH = "#{BIND_PATH}/var"
	SAVE_PATH = "#{ZONE_PATH}/saved"
	DNSSEC_PATH = "#{ZONE_PATH}/dnssec"
	DANE_CERT = "/etc/postfix/postfix.pem"
	MX_HOST = "mail"

In dnssec.sh:

	Update the command to reflect installation path, and path to Ruby.

# USAGE

./dnssec.rb --list
	List all domains for which this server acts as primary nameserver

./dnssec.rb --list-secure
	Same as list, but only when DNSSEC enabled

./dnssec.rb --list-insecure
	Same as list, but only when DNSSEC is not enabled

./dnssec.rb --sign example.com
	Signs the given domain

./dnssec.rb --re-sign example.com
	Re-signs a previously signed zone if a RRSIG record expires in the cycle interval

./dnssec.rb --re-sign-all
	Re-signs previously signed zones if a RRSIG record expires in the cycle interval

./dnssec.rb --un-sign example.com
	Unsigns a previously signed zone

./dnssec.rb --un-sign-all
	Unsigns all previously signed zones

./dnssec.rb --check-dnssec
	Ensures that DNSSEC is enabled for domains with a pregenerated key

./dnssec.rb --handle-plesk-event
	Handles Plesk Event (in combination with --event)

./dnssec.rb --event [EVENT]
	Select Plesk event type (dns_zone_updated)

# ENABLING DNSSEC FOR A SINGLE DOMAIN

Executing,

	./dnssec.rb --sign example.com
	
yields,

	Algorithm: RSASHA1: 
	KSKs: 1 active, 0 stand-by, 0 revoked
    ZSKs: 1 active, 0 stand-by, 0 revoked
	example.com. 3600 IN DS 53911 5 1 4290E47A1E86CBF1BEA2AE43&563DD9BABD2CF31

Log into your Registrar account for example.com and configure the DS record for the domain.

Finally, set up a cron job to resign the zone:

  0 6 * * 1 /usr/local/autodnssec/dnssec.sh --re-sign

Logs may be found at:

	/var/log/dnssec.log

Note that autodnssec will add an equivalent SPF record for any unmatched TXT record in the zone.

# INTEGRATING WITH PLESK

Log into Plesk and configure the following Events:

* Default domain, alias DNS zone updated
* Default domain, DNS zone updated
* Domain alias DNS zone updated
* Domain DNS zone updated
* Subdomain DNS zone updated

With the command:

	/usr/local/autodnssec/dnssec.sh --handle-plesk-event --event dns_zone_updated

