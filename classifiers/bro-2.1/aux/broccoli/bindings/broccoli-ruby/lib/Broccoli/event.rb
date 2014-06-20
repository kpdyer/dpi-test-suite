module Broccoli
  
  class Event
    include Broccoli_ext
    attr_reader :ev
    
    def initialize(name)
      @ev = bro_event_new(name)
      # Kill the BroEvent when the ruby object is garbage collected
      ObjectSpace.define_finalizer(self, Event.create_finalizer(@ev))
    end

    # Insert a value into an event.
    def insert(value, type, type_name=nil)
      value = value.rec if type == :record
      bro_event_add_val(@ev, [Broccoli::TYPES[type], type_name, value])
    end
    
    private
    
    # Free the underlying C event data structure.  User's are likely 
    # never going to need this call.
    def free
      bro_event_free(@ev)
    end
    
    # When the garbage collector comes around, make sure the C structure
    # is freed.
    def self.create_finalizer(event)
      proc { bro_event_free(event) }
    end
  end

end