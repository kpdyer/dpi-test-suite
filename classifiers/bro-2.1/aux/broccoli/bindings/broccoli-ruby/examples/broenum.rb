#!/usr/bin/env ruby

require 'broccoli'

require 'logger'
require 'optparse'
require 'ostruct'
require 'ipaddr'

class BroenumApp < Logger::Application
  include Broccoli
  
  def run
    opt = parse_opts()
      
    # Set debugging vars
    Broccoli.debug_messages=true if opt.debug > 0  
    Broccoli.debug_calltrace=true if opt.debug > 1
    
    # Create the connection object
    bc = Broccoli::Connection.new("#{opt.host}:#{opt.port}")
        
    if bc.connect
      puts "connected"
      ev = Broccoli::Event.new("enumtest")
      ev.insert(opt.num, :enum, opt.type_name)
      puts "Sending enum val #{opt.num} to remote peer."
      bc.send(ev)

      # Make sure the event isn't still queued
      while bc.queue_length > 0
        bc.queue_flush
      end
      
      bc.disconnect
    else
      puts "Couldn't connect to Bro server at #{opt.host}:#{opt.port}."
    end
    
  end
  
  private
  
  def initialize
    super('app')
    STDERR.sync = true
    self.level = Logger::FATAL
  end
    
  def parse_opts
    options = OpenStruct.new
    options.debug = 0
    options.host = "127.0.0.1"
    options.port = 47758
    options.type_name = "enumtest::enumtype"
    options.num = 0
    
    opts = OptionParser.new do |opts|
      opts.banner = "broenum - sends enum vals to a Bro node, printing the corresponding
      	 string value on the Bro side.
      	 USAGE: #{$0} [-h] [-d] [-p port] [-t type] [-n num] host"

      opts.separator ""
      opts.separator "Specific options:"
      
      opts.on('-p', '--port PORT',
              'The port your bro agent is listening on') do |port|
        options.port = port.to_i
      end
      
      opts.on('-n', '--num NUM',
              'The enum value') do |n|
        options.num = n.to_i
      end
      
      opts.on('-t', '--type TYPE',
              'The enum type') do |t|
        options.type_name = t
      end
                  
      opts.separator ""
      opts.separator "Common options:"

      # No argument, shows at tail.  This will print an options summary.
      # Try it and see!
      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end
      
      opts.on_tail('-d', '--debug',
              'Use this option once for debug messages and twice for calltraces') do
        options.debug += 1
      end
      
    end
    
    begin
      opts.parse!(ARGV)       
      raise(OptionParser::InvalidOption, "missing host") unless ARGV[0]
      options.host = ARGV[0]
    rescue OptionParser::InvalidOption => e
      puts "Invalid option! (#{e})"
      puts opts
      exit -1
    end
    options
  end
  
end

begin
  BroenumApp.new.start
rescue Interrupt => e
  # Catch interrupts quietly
end
