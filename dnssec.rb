#!/usr/bin/env ruby

# autodnssec v0.1: dnssec.rb
#
# Copyright (c) 2014, Tamer Rizk and Rene van Lieshout.
# This is free, open source software, licensed under the Revised BSD License.
# Please feel free to use and distribute it accordingly.
#

require "optparse"
require "pp"

require File.join(File.dirname(__FILE__), "dnssec", "options")
require File.join(File.dirname(__FILE__), "dnssec", "list")
require File.join(File.dirname(__FILE__), "plesk")

class DNSSec
	include Options
	include List

	BIND_PATH = "/var/named/chroot"
	ZONE_PATH = "#{BIND_PATH}/var"
	SAVE_PATH = "#{ZONE_PATH}/saved"
	DNSSEC_PATH = "#{ZONE_PATH}/dnssec"
	DANE_CERT = "/etc/postfix/postfix.pem"
	MX_HOST = "mail"

	def initialize(args)
		parse_options(args)
		Dir.mkdir(DNSSEC_PATH) unless File.exists?(DNSSEC_PATH)
		Dir.mkdir(SAVE_PATH) unless File.exists?(SAVE_PATH)
		@bin = { "openssl" => "/usr/bin/openssl", "named" => "/usr/sbin/named", "dnssec-keygen" => "/usr/sbin/dnssec-keygen", "dnssec-signzone" => "/usr/sbin/dnssec-signzone", "dnssec-dsfromkey" => "/usr/sbin/dnssec-dsfromkey", "service" => "/sbin/service", "rm" => "/bin/rm", "cd" => "/bin/cd", "cp" => "/bin/cp", "mv" => "/bin/mv", "echo" => "/bin/echo", "grep" => "/bin/grep", "cat" => "/bin/cat"}
		@bin.each do |k,v|
			@bin[k] = `command -v '#{k}'`.gsub(/[\r\n\t]/, " ").sub(/^[^\/]+\//, "/").sub(/^[^']+'/, "").gsub(/(?:^[ ]+)|([ ].*$)/, "") if !File.exists?(v)
			abort("Could not find #{k} in PATH") if @bin[k].empty?
		end

		@tlsa_data = (!DANE_CERT.empty? && File.exists?(DANE_CERT)) ? `#{@bin['openssl']} x509 -noout -fingerprint -sha256 < #{DANE_CERT} | tr -d :`.gsub(/^.*=/, "") : ""
		make_sure_named_has_dnssec_enabled!
		execute_action
	end

	def execute_action
		@reload = false
 		case @action
 			when :list then list_domains
			when :list_secure then list_domains(:secure)
			when :list_insecure then list_domains(:insecure)
			when :sign then sign(@domain)
			when :re_sign_all then re_sign_all
			when :re_sign then re_sign(@domain)
			when :un_sign_all then un_sign_all
			when :un_sign then un_sign(@domain)
			when :check_dnssec then check_dnssec
			when :handle_plesk_event then re_sign(ENV["NEW_DOMAIN_ALIAS_NAME"] || ENV["NEW_DOMAIN_NAME"])
		end

		if @reload
			now = Time.now.to_i.to_s
			exit if now.to_i != `#{@bin['echo']} -n #{now} > /tmp/dnssec.rb.ts && sleep 2 && #{@bin['cat']} /tmp/dnssec.rb.ts`.to_i
			puts `#{@bin['service']} named-chroot reload`
		end
	end

	def make_sure_named_has_dnssec_enabled!
		bind_version = `#{@bin['named']} -v`
		bind_version = bind_version.gsub(/^.*?\s/,"").gsub(/\.\d-.*\n/,"")
		if bind_version.to_i < 9 || (bind_version.to_i == 9 && bind_version.gsub(/^9\./,"").gsub(/\..*$/,"").to_i<4)
			abort("dnssec.rb requires BIND 9.4 or newer to function. Please upgrade #{bind_version.to_s} to something newer...")
		end

		unless /dnssec-enable\s*yes/ =~ File.read("#{BIND_PATH}/etc/named.conf")
			abort("dnssec.rb requires BIND to have DNSSEC enabled. Please enable DNSSEC by adding dnssec-enable yes; to the options part of #{BIND_PATH}/etc/named.conf")
		end
	end

	def key_exists?(domain)
		!Dir[File.join(DNSSEC_PATH, "K#{domain}*")].empty?
	end

	def safe_exec(command)
		system(command) || raise("Command #{command} failed...")
	end

	def is_signed?(domain)
		`#{@bin['grep']} -i RRSIG #{ZONE_PATH}/#{domain}` =~ /\bRRSIG\b/i
	end

	def has_tlsa?(domain)
		`#{@bin['grep']} -i TLSA #{ZONE_PATH}/#{domain}` =~ /\bTLSA\b/i
	end

	def has_spf?(domain)
		`#{@bin['grep']} -i SPF #{ZONE_PATH}/#{domain}` =~ /\bIN[\t ]+SPF\b/i
	end

	def create_tlsa(domain)
		if !@tlsa_data.empty? && !is_signed?(domain) && !has_tlsa?(domain)
			safe_exec "#{@bin['echo']} '_465._tcp.#{MX_HOST}.#{domain}. IN TLSA 3 0 1 #{@tlsa_data}' >> #{ZONE_PATH}/#{domain}"
			safe_exec "#{@bin['echo']} '_587._tcp.#{MX_HOST}.#{domain}. IN TLSA 3 0 1 #{@tlsa_data}' >> #{ZONE_PATH}/#{domain}"
			safe_exec "#{@bin['echo']} '_993._tcp.#{MX_HOST}.#{domain}. IN TLSA 3 0 1 #{@tlsa_data}' >> #{ZONE_PATH}/#{domain}"
			safe_exec "#{@bin['echo']} '_995._tcp.#{MX_HOST}.#{domain}. IN TLSA 3 0 1 #{@tlsa_data}' >> #{ZONE_PATH}/#{domain}"
		end
	end

	def create_spf(domain)
		txt = ""
		if !is_signed?(domain) && !has_spf?(domain)
			txt = `#{@bin['grep']} -Pi 'IN[\t ]*TXT[^=]+v[\t ]*=[\t ]*spf' #{ZONE_PATH}/#{domain}`
			if !txt.empty?
				txt = txt.gsub(/IN[\t ]+TXT/i, "IN SPF").gsub(/'/, "\"")
				safe_exec "#{@bin['echo']} '#{txt}' >> #{ZONE_PATH}/#{domain}"
			end
		end
	end

	def backup_zone(domain, now="")
		now = Time.now.to_i.to_s if now.empty?
		safe_exec "#{@bin['rm']} -f #{SAVE_PATH}/#{domain}.saved.*"
		safe_exec "#{@bin['cp']} #{ZONE_PATH}/#{domain} #{SAVE_PATH}/#{domain}.saved.#{now}"
		if !is_signed?(domain)
			safe_exec "#{@bin['rm']} -f #{SAVE_PATH}/#{domain}.unsigned"
			safe_exec "#{@bin['cp']} #{ZONE_PATH}/#{domain} #{SAVE_PATH}/#{domain}.unsigned"
		end
	end

	def sign(domain)
		if domain.nil? || domain == ""
			puts "No domain specified"
			exit
		end

		puts "Validating #{domain}..." ; STDOUT.flush

		unless domain_list.include?(domain)
			puts "We are not the pimary nameserver for Domain #{domain}..."
			exit
		end

		if is_signed?(domain) || domain_list(:secure).include?(domain)
			puts "Domain #{domain} is already secure..."
			# exit
		end

		zsk = ksk = ""
		now = Time.now.to_i.to_s
		new_keys = !key_exists?(domain)

		if new_keys
			puts "Generating keys for #{domain}..." ; STDOUT.flush

			zsk_file = `#{@bin['dnssec-keygen']} -K #{DNSSEC_PATH} -r /dev/urandom -a RSASHA1 -b 1024 -n ZONE #{domain} | tail -1`
			ksk_file = `#{@bin['dnssec-keygen']} -K #{DNSSEC_PATH} -r /dev/urandom -a RSASHA1 -b 2048 -n ZONE -f KSK #{domain} | tail -1`

			zsk = File.read(DNSSEC_PATH + "/" + zsk_file.gsub(/\n/,".key")).gsub(/;.*?\n/, "").gsub(/^.*IN DNSKEY 256 3 5 /, "").gsub(/\n/, "")
			ksk = File.read(DNSSEC_PATH + "/" + ksk_file.gsub(/\n/,".key")).gsub(/;.*?\n/, "").gsub(/^.*IN DNSKEY 257 3 5 /, "").gsub(/\n/, "")

		end

		begin
			backup_zone(domain, now)
			create_spf(domain)
			create_tlsa(domain)
			safe_exec "#{@bin['cat']} #{DNSSEC_PATH}/K#{domain}.*.key >> #{ZONE_PATH}/#{domain}"
			safe_exec "#{@bin['dnssec-signzone']} -K #{DNSSEC_PATH} -N INCREMENT -o #{domain} #{ZONE_PATH}/#{domain}"

			puts `#{@bin['dnssec-dsfromkey']} -1 -f #{ZONE_PATH}/#{domain}.signed #{domain}`.gsub(/IN[ \t]+DS/, "3600 IN DS")
			STDOUT.flush

			safe_exec "#{@bin['cp']} #{ZONE_PATH}/#{domain}.signed #{ZONE_PATH}/#{domain}"
			safe_exec "#{@bin['rm']} -f #{ZONE_PATH}/#{domain}.signed"
			@reload = true

		rescue
			safe_exec "#{@bin['mv']} #{ZONE_PATH}/#{domain} #{SAVE_PATH}/#{domain}.bak.#{now}"
			safe_exec "#{@bin['cp']} #{SAVE_PATH}/#{domain}.saved.#{now} #{ZONE_PATH}/#{domain}"
			if new_keys
				`#{@bin['rm']} -rf #{DNSSEC_PATH}/K#{domain}.*`
				`#{@bin['rm']} -rf #{DNSSEC_PATH}/*set*#{domain}*`
			end
			raise $!
		end
	end

	def un_sign(domain)
		if is_signed?(domain) || domain_list(:secure).include?(domain)
			backup_zone(domain)
			if File.exists?("#{SAVE_PATH}/#{domain}.unsigned")
				safe_exec "#{@bin['cp']} #{SAVE_PATH}/#{domain}.unsigned #{ZONE_PATH}/#{domain}"
				@reload = true
			else
				puts "Could not unsign #{domain}..."
				return
			end
		end
	end

	def un_sign_all
		domain_list(:secure).each do |domain|
			puts "Unsigning #{domain}..."
			un_sign(domain)
		end
	end

	def re_sign(domain)
		if domain.nil? || domain == ""
			puts "No domain specified"
			return
		end

		unless domain_list.include?(domain)
			puts "We are not the pimary nameserver for Domain #{domain}..."
			return
		end

		if !key_exists?(domain)
			puts "No key for #{domain}..."
			return
		end

		puts "Re-signing #{domain}..."
		backup_zone(domain)
		create_spf(domain)
		create_tlsa(domain)
		safe_exec "#{@bin['cat']} #{DNSSEC_PATH}/K#{domain}.*.key >> #{ZONE_PATH}/#{domain}"
		`#{@bin['dnssec-signzone']} -K #{DNSSEC_PATH} -o #{domain} #{ZONE_PATH}/#{domain}`
		puts `#{@bin['dnssec-dsfromkey']} -1 -f #{ZONE_PATH}/#{domain}.signed #{domain}`.gsub(/IN[ \t]+DS/, "3600 IN DS")
		`#{@bin['cp']} #{ZONE_PATH}/#{domain}.signed #{ZONE_PATH}/#{domain}`
		safe_exec "#{@bin['rm']} -f #{ZONE_PATH}/#{domain}.signed"

		@reload = true

	end

	def re_sign_all
		now = Time.now.to_i.to_s
		domain_list(:secure).each do |domain|
			re_sign(domain) if is_signed?(domain)
		end
	end

	def check_dnssec
		domain_list(:secure).each do |domain|
			re_sign(domain) if !is_signed?(domain)
		end
	end

end

DNSSec.new(ARGV)
[root@klaver autodnssec]# cd /usr/local/autodnssec/
[root@klaver autodnssec]# ls -altr
totaal 56
drwxr-xr-x. 16 root root 4096 12 aug 16:22 ..
-rw-------   1 root root 2648  1 dec 16:39 README.md
-rw-------   1 root root 1577  1 dec 16:39 LICENSE
-rw-------   1 root root   44  1 dec 16:39 Gemfile
drwx------   3 root root 4096  1 dec 16:39 misc
-rwx------   1 root root  103  1 dec 16:39 dnssec.sh
drwx------   2 root root 4096  1 dec 16:39 dnssec
-rw-------   1 root root  373  1 dec 16:39 plesk.rb
-rw-------   1 root root  163  1 dec 17:26 dsset-malbum.nl.
drwx------   5 root root 4096  1 dec 17:26 .
drwx------   8 root root 4096  1 dec 17:29 .git
-rwx------   1 root root 8476  1 dec 17:33 dnssec.rb
[root@klaver autodnssec]# ls -altr dnssec
totaal 16
-rw------- 1 root root 3322  1 dec 16:39 options.rb
drwx------ 2 root root 4096  1 dec 16:39 .
-rw------- 1 root root 1683  1 dec 16:54 list.rb
drwx------ 5 root root 4096  1 dec 17:26 ..
[root@klaver autodnssec]#
[root@klaver autodnssec]# pwd
/usr/local/autodnssec
[root@klaver autodnssec]# diff dnssec/
list.rb     options.rb
[root@klaver autodnssec]# diff dnssec/list.rb /usr/local/src/autodnssec/dnssec/list.rb
\43,45c43,45
<         SELECT domain_aliases.name
<         FROM domain_aliases
<         INNER JOIN dns_zone ON domain_aliases.dns_zone_id = dns_zone.id
---
>         SELECT domainaliases.name
>         FROM domainaliases
>         INNER JOIN dns_zone ON domainaliases.dns_zone_id = dns_zone.id
48c48
<         AND domain_aliases.status = 0
---
>         AND domainaliases.status = 0
[root@klaver autodnssec]#
[root@klaver autodnssec]# cat dnssec/list.rb
class DNSSec
  module List
    # Prints a list of domains for which this
    # server acts as primary nameserver
    #
    # Optional filter: one of :secure or :insecure
    # to list only domains with or without dnssec
    def list_domains(filter = nil)
      domains = domain_list(filter)

      puts "Domains for which this server acts as primary nameserver:"
      puts ""
      if filter
        puts "Filter: #{filter}"
        puts
      end

      domains.each do |domain|
        puts "* #{domain}"
      end

      puts "" if domains.length > 0
      puts "Domains listed: #{domains.length}"

    end

    # Returns a list of domains for which this
    # server acts as primary nameserver
    #
    # Optional filter: one of :secure or :insecure
    # to list only domains with or without dnssec
    def domain_list(filter = nil)
      domains = Plesk.instance.query_database("
        SELECT domains.name
        FROM domains
        INNER JOIN dns_zone ON domains.dns_zone_id = dns_zone.id
        AND dns_zone.status = 0
        AND dns_zone.type = 'master'
        AND domains.status = 0

        UNION ALL

        SELECT domain_aliases.name
        FROM domain_aliases
        INNER JOIN dns_zone ON domain_aliases.dns_zone_id = dns_zone.id
        AND dns_zone.status = 0
        AND dns_zone.type = 'master'
        AND domain_aliases.status = 0

        ORDER BY name
      ")

      if filter
        domains = domains.select do |domain|
          is_secure = key_exists?(domain["name"])
          (filter == :secure && is_secure) || (filter == :insecure && !is_secure)
        end
      end

      return domains.map{ |domain| domain["name"] }
    end
  end
end
