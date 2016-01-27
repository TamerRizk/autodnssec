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
