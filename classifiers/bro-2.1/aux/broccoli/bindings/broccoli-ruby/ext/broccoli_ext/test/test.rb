# Please don't try to read too much into this file.  It's mostly my 
# internal test file while I'm building the C binding.
#
# Check out the examples directory for better examples that use the ruby
# library I've built overtop the C bindings.

require './broccoli_ext'
include Broccoli_ext
Broccoli_ext::bro_debug_calltrace=false
Broccoli_ext::bro_debug_messages=false

STDOUT.sync = true

#a= Broccoli_ext::BroString.new
#a.str_val="asdf"

host_str = "127.0.0.1:12345"

bc = bro_conn_new_str(host_str, BRO_CFLAG_NONE)
puts "Connection? #{bc}"
#puts "  Connected" unless bro_conn_connect(bc).zero?

###
# Test BroString Creation
###

module SWIG
  class TYPE_p_bro_conn
    def method_missing(meth, *args)
      return bro_conn_data_get(self, meth.id2name)
    end
  end
  
  class TYPE_p_bro_record
    # I need to build a full record typemapper to deal with this correctly.
    
    def method_missing(meth, *args)
      #return bro_record_get_named_val(self, meth.id2name, BRO_TYPE_STRING)
    end
    
    def [](position)
      #return bro_record_get_nth_val(self, position, BRO_TYPE_STRING)
    end
  end
end



###
# Test Record Creation
###
#rec = bro_record_new()
#puts "Ruby: Inserting data into the record"
##time = bro_util_current_time()
##puts "Ruby: Current time: #{time}"
#bro_record_add_val(rec, "seq", BRO_TYPE_IPADDR, 213054988)
#puts "Ruby: Getting the data back out"
##puts bro_record_get_named_val(rec, "seq", BRO_TYPE_COUNT);
#puts "  " + bro_record_get_nth_val(rec, 0, BRO_TYPE_IPADDR).to_s



###
# Test Callback creation
###

# Ideal :)
#bro_ruby_typemap_new("pong", [8,19,0])
#build_typemap("pong", [:conn,:record])

#while 1
#  ev = bro_event_new("ping")
#  bro_event_free(ev)
#  #GC.start
#end

bro_pong_record = Proc.new do |conn, rec|
  now = bro_util_current_time()
  puts "Pong_record callback"
  puts rec

  seq = bro_record_get_nth_val(rec, 0, BRO_TYPE_COUNT)
  src_time = bro_record_get_nth_val(rec, 1, BRO_TYPE_TIME)
  dst_time = bro_record_get_nth_val(rec, 2, BRO_TYPE_TIME)
  
  puts "pong event from #{host_str}: seq=#{seq}, time=#{dst_time-src_time}/#{now-src_time} s"
end

bro_pong = Proc.new do |conn, src_time, dst_time, seq|
  puts "Pong callback!"
  now = bro_util_current_time()
  puts "pong event from #{host_str}: seq=#{seq}, time=#{dst_time-src_time}/#{now-src_time} s"
end

new_connection = Proc.new do |conn|
  puts "Saw a connection!"
end

dns_request = Proc.new do |conn, msg, query, qtype, qclass|
  #$count = $count+1
  #puts "msg: #{msg}"
  #puts "query: #{query}"
  #puts "qtype: #{qtype}"
  #puts "qclass: #{qclass}"
  #puts "service: #{conn.blah}"
  #puts "Query output class: #{query.class}"
  #answers = bro_record_get_nth_val(msg, 11, BRO_TYPE_COUNT).to_s
  #puts "Number of dns answers: #{answers}"
  #puts "Query: #{query} - Query type: #{qtype} - Query class: #{qclass}"
end

#puts "Registering callback..."
#bro_event_registry_add(bc, "dns_A_reply", dns_reply)

bro_event_registry_add(bc, "dns_request", ["dns_request", [19, 19, 8, 3, 3], dns_request])

#bro_event_registry_add(bc, "pong", ["pong", {"pong", [19]}, bro_pong_record])
#bro_event_registry_add(bc, "pong", ["pong", {"pong", [6,6,3]}, bro_pong])

#bro_event_registry_add(bc, "wootback", [[8], wootback])

#bro_event_registry_add(bc, "new_connection", ["new_connection", {"new_connection", [19]}, new_connection])
#bro_event_registry_add(bc, "return_memory", return_memory)

#puts "Done Registering callback..."
puts "Connected" if bro_conn_connect(bc)

while(1)
  #puts "Checking input"
  $count = 0
  bro_conn_process_input(bc)
  puts "*" * ($count/2)
  
  sleep 0.5
  
  GC.start
end
exit

###
# Testing record creation and event sending
###
record = false
(1..100).each do |seq|
  bro_conn_process_input(bc)
  #puts "Creating event"
  ev = bro_event_new("ping")
  timestamp = bro_util_current_time()
  if(record)
    rec = bro_record_new()
    bro_record_add_val(rec, "seq", BRO_TYPE_COUNT, seq)
    bro_record_add_val(rec, "src_time", BRO_TYPE_TIME, timestamp)
    bro_event_add_val(ev, BRO_TYPE_RECORD, rec)
  else
    bro_event_add_val(ev, BRO_TYPE_TIME, timestamp)
    bro_event_add_val(ev, BRO_TYPE_COUNT, seq)
  end
  
  puts "Sending ping..."
  bro_event_send(bc, ev)
  # May not need to call this anymore either
  #bro_event_free(ev)
  sleep 1
  #GC.start
end

#while(1) do
#  ev = bro_event_new "show_memory"
#  puts "Sending event"
#  puts bro_event_send(bc, ev)
#  sleep 1
#  puts "Processing input..."
#  puts bro_conn_process_input(bc)
#end
