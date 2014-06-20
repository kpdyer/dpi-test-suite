#!/usr/bin/env ruby

require 'broccoli'

require 'ipaddr'
require 'time'

# Set debugging vars
#Broccoli_ext::bro_debug_messages=true
#Broccoli_ext::bro_debug_calltrace=true

bc = Broccoli::Connection.new("localhost:47758")

bc.event_handler_for "dns_request" do |c, msg, query, qtype, qclass|
  begin
    src = IPAddr.ntop(c.id.orig_h)
    dst = IPAddr.ntop(c.id.resp_h)
  rescue
    print "bug!"
  end
  time = Time.at(c.start_time).strftime("%Y-%m-%d %H:%M:%S")
  puts "#{time} #{src}:#{c.id.orig_p} -> #{dst}:#{c.id.resp_p} #{query}"
end

if bc.connect
  puts "connected"
  while bc.wait
    bc.process_input
  end
else
  puts "Could not connect to server"
end
