#!/usr/bin/env ruby

require 'broccoli'

require 'logger'
require 'optparse'
require 'ostruct'
require 'ipaddr'

class BropingApp < Logger::Application
  def run
    opt = parse_opts()
      
    # Set debugging vars
    Broccoli.debug_messages=true if opt.debug > 0  
    Broccoli.debug_calltrace=true if opt.debug > 1
      
    # Create the connection object
    bc = Broccoli::Connection.new("#{opt.host}:#{opt.port}")
    
    if opt.record
      # Register the pong event handler
      bc.event_handler_for "pong" do |p|
        now = Broccoli::current_time_f  
        printf "pong event from %s: seq=%i, time=%6f/%6f s\n", opt.host,
                                                               p.seq,
                                                               p.dst_time-p.src_time,
                                                               now-p.src_time;
      end
    else
      # Register the pong event handler
      bc.event_handler_for "pong" do |src_time, dst_time, seq|
        now = Broccoli::current_time_f
        printf "pong event from %s: seq=%i, time=%6f/%6f s\n", opt.host,
                                                               seq,
                                                               dst_time.to_f-src_time.to_f,
                                                               now-src_time;
        
      end
    end
    
    if bc.connect
      seq = 0
      #puts "connected"
      while true
        break if opt.count > 0 && seq == opt.count

        ev = Broccoli::Event.new("ping")        
        if opt.record
          rec = Broccoli::Record.new
          rec.insert("seq", seq, :count)
          rec.insert("src_time", Broccoli::current_time_f, :time)
          ev.insert(rec, :record)
        else
          ev.insert(Broccoli.current_time_f, :time)
          ev.insert(seq, :count)
        end
        bc.send(ev)
        sleep 1
        bc.process_input
        seq += 1
      end
    else
      puts "Couldn't connect to Bro server."
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
    options.port = 47758
    options.count = -1
    options.record = false
    
    opts = OptionParser.new do |opts|
      opts.banner = "broping - sends ping events to a Bro agent, expecting pong events (written in ruby).\nUsage: #{$0} [options] host"

      opts.separator ""
      opts.separator "Specific options:"
      
      opts.on('-p', '--port PORT',
              'The port your bro agent is listening on') do |port|
        options.port = port
      end
      
      opts.on('-c', '--count COUNT',
              'The number of pings you\'d like to send (10 by default)') do |c|
        options.count = c.to_i
      end
      
      opts.on('-r', '--records',
              'Send ping records to the bro instance instead of event arguments') do
        options.record = true
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
      exit
    end
    options
  end
  
end

begin
  BropingApp.new.start
rescue Interrupt => e
  # Catch interrupts quietly
end
