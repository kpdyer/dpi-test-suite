#!/usr/bin/env ruby

require 'broccoli_ext'
include Broccoli_ext

peer = bro_conf_get_str("PeerName")
puts "Peer: #{peer}"

#ret, port = bro_conf_get_int("PeerPort")
#if(ret)
#  puts "PeerPort: #{ret}"
#end
