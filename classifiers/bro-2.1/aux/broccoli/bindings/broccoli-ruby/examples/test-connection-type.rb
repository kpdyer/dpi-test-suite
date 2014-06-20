#!/usr/bin/env ruby

require 'broccoli'

require 'ipaddr'
include Broccoli

Broccoli.debug_messages=true
Broccoli.debug_calltrace=false

bc = Broccoli::Connection.new("127.0.0.1:47758", BRO_CFLAG_CACHE)

bc.event_handler_for("test_conn") { |c| 
  puts IPAddr.ntop(a.id.orig_h).to_s
  print "do it!"
}

if bc.connect
  puts "connected"
  while bc.wait
    bc.process_input
  end
end
