require 'rubygems'
require 'mysql2'
require 'singleton'

class Plesk
  include Singleton

  def query_database(query)
    mysql_connect
    @client.query(query)    
  end

  private

  def mysql_connect
    @client ||= Mysql2::Client.new(:host => "localhost", :username => "admin", :password => File.read("/etc/psa/.psa.shadow").gsub(/\n/,""), :database => "psa")
  end
end