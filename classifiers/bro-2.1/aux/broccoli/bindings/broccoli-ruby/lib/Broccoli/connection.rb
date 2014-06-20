# This gives a nice interface for retrieving fields from connections
module SWIG
  class TYPE_p_bro_conn    
    def method_missing(meth, *args)
      return Broccoli::bro_conn_data_get(self, meth.id2name)
    end
  end
end

module Broccoli
  class Connection
    include Broccoli_ext
    
    def initialize(hp, flags=nil)
      # Initialize the library first.
      bro_init(nil);
      
      flags ||= (BRO_CFLAG_RECONNECT | BRO_CFLAG_ALWAYS_QUEUE)
      @bc = bro_conn_new_str(hp, flags)
      @io_object = nil
      @event_blocks = []
    end
    
    def disconnect
      bro_conn_delete(@bc)
    end

    def connect
      bro_conn_connect(@bc)
    end

    def connected?
      bro_conn_alive?(@bc)
    end

    def process_input
      bro_conn_process_input(@bc)
    end
    
    def queue_length
      bro_event_queue_length(@bc)
    end
    
    def queue_length_max
      bro_event_queue_length_max(@bc)
    end
        
    def queue_flush
      bro_event_queue_flush(@bc)
    end
    
    def send(event)
      # .ev is the real event pointer
      bro_event_send(@bc, event.ev)
    end
        
    def wait
      unless @io_object
        fd = bro_conn_get_fd(@bc)
        return false if fd < 0
        @io_object = IO.new(fd)
        @io_object.sync = true # don't buffer
      end
      # block until there is data
      if @io_object.closed?
        puts "ERROR: connection lost!"
        exit(-1)
      else
        IO.select([@io_object])
      end
    end
    
    def event_handler(event, &callback)
      bro_event_registry_add_compact(@bc, event, callback)   
      # Re-request all events if we're already connected.
      bro_event_registry_request(@bc) if connected?
    end
    alias :event_handler_for :event_handler
    
  end
end
