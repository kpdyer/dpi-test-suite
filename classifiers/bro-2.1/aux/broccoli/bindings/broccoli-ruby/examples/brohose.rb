#!/usr/bin/env ruby

require 'broccoli'

require 'logger'
require 'optparse'
require 'ostruct'
require 'ipaddr'

class BrohoseApp < Logger::Application
  include Broccoli
  
  def run
    opt = parse_opts()
      
    # Set debugging vars
    Broccoli.debug_messages=true if opt.debug > 0  
    Broccoli.debug_calltrace=true if opt.debug > 1
      
    printf("Will attempt to send %i events from %i processes, to %s\n",
           opt.events, opt.processes, opt.host)
    puts "enter to continue"
    STDIN.gets
    
    # Create the connection object
    bc = Broccoli::Connection.new("#{opt.host}:#{opt.port}")
        
    if bc.connect
      #puts "connected"

      (1..opt.processes).each do
        @pid = fork()
        
        if @pid.nil?
          hose_away(bc, opt.events)
          exit 0
        end
        
        if @pid < 0
          puts "Unable to fork children, aborting."
          exit -1
        end
                              
      end
      
      Process.wait
      puts "All children finished... done."
      exit 0
      
    else
      puts "Couldn't connect to Bro at #{opt.host}:#{opt.port}."
      exit -1
    end
    
  end
  
  private
  
  def initialize
    super('app')
    STDERR.sync = true
    self.level = Logger::FATAL
    
    @pid = 0
  end
  
  def hose_away(bc, events)
    (1..events).each do |i|
      ev = Broccoli::Event.new("brohose")  
      msg = sprintf("%u-%i-%i", @pid, i, bc.queue_length) 
      ev.insert(msg, :string)
      bc.send(ev) 
    
      if (bc.queue_length > bc.queue_length_max/2)
    	  while bc.queue_length > 0
    	    bc.queue_flush
  	    end
    	end
    	
    end
    
	  while bc.queue_length > 0
	    bc.queue_flush
    end

    printf("-- child %u, %i queued\n", @pid, bc.queue_length)
    bc.disconnect
  end
    
  def parse_opts
    options = OpenStruct.new
    options.debug = 0
    options.port = 47758
    options.processes = 10
    options.events = 1000
    
    opts = OptionParser.new do |opts|
      opts.banner = "brohose - Try to hose bro with data.\nUsage: #{$0} [options] host"

      opts.separator ""
      opts.separator "Specific options:"
      
      opts.on('-p', '--port PORT',
              'The port your bro agent is listening on') do |port|
        options.port = port
      end
      
      opts.on('-n', '--number NUMBER',
              'Number of processes to use (10)') do |n|
        n = n.to_i
        if n < 1 or n > 100  
          puts "Please restrict the number of processes to 1-100."
          exit -1
        end
        options.processes = n
      end
      
      opts.on('-e', '--events EVENTS',
              'Number of events per process (1000)') do |e|
        e = e.to_i
        if e < 1 or e > 10000  
          puts "Please restrict the number of events to 1-10,000."
          exit -1
        end
        options.events = e
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
  BrohoseApp.new.start
rescue Interrupt => e
  # Catch interrupts quietly
end
