class DNSSec
  module Options
    # Parses command line options and sets
    # @action and @plesk_event
    def parse_options(args)
      @action = nil
      @plesk_event = nil
      @domain = nil

      multiple_actions = false

      opts = OptionParser.new do |opts|
        opts.banner = "Usage: dnssec.rb [options]"

        opts.separator ""
        opts.separator "Specific options:"

        opts.on("--list", "List all domains for which this server acts as primary nameserver") do
          multiple_actions = true if @action
          @action = :list
        end

        opts.on("--list-secure", "Same as list, but only when DNSSEC enabled") do
          multiple_actions = true if @action
          @action = :list_secure
        end

        opts.on("--list-insecure", "Same as list, but only when DNSSEC is not enabled") do
          multiple_actions = true if @action
          @action = :list_insecure
        end

        opts.on("--sign [domain]", "Signs the given domain") do |domain|
          @action = :sign
          @domain = domain
        end

        opts.on("--re-sign [domain]", "Re-signs a previously signed zone if a RRSIG record expires in the cycle interval") do |domain|
          @domain = domain
          @action = :re_sign
        end

        opts.on("--re-sign-all", "Re-signs previously signed zones if a RRSIG record expires in the cycle interval") do
          @action = :re_sign_all
        end

        opts.on("--un-sign [domain]", "Unsigns a previously signed zone") do |domain|
          @domain = domain
          @action = :un_sign
        end

        opts.on("--un-sign-all", "Unsigns all previously signed zones") do
          @action = :un_sign_all
        end

        opts.on("--check-dnssec", "Ensures that DNSSEC is enabled for domains with a key") do
          @action = :check_dnssec
        end

        opts.on("--handle-plesk-event", "Handles Plesk Event (in combination with --event)") do
          multiple_actions = true if @action
          @action = :handle_plesk_event
        end

        opts.on(
          "--event [EVENT]",
          [:dns_zone_updated],
          "Select Plesk event type (dns_zone_updated)",
          " ",
          "There are several events handlers that should be added in Plesk:",
          " ",
          "* Default domain, alias DNS zone updated",
          "* Default domain, DNS zone updated",
          "* Domain alias DNS zone updated",
          "* Domain DNS zone updated",
          "* Subdomain DNS zone updated",
          " ",
          "Command: #{`pwd`.gsub(/\n/,"")}/dnssec.sh --handle-plesk-event --event dns_zone_updated",
          " "
        ) do |event|
          @plesk_event = event
        end

        opts.separator ""
        opts.separator "Common options:"

        opts.on_tail("-h", "--help", "Show this message") do
          puts opts
          exit
        end

        opts.on_tail("--version", "Show version") do
          puts "0.1"
          exit
        end
      end

      begin
        opts.parse!(args)
      rescue
        @action = nil
      end

      @action = nil if @action == :handle_plesk_event && @plesk_event.nil?
      @action = nil if @action == :sign && @domain.nil?

      if @action.nil? || multiple_actions
        puts opts
        exit
      end

    end
  end
end
