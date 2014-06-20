# This gives a nice interface for retrieving fields from records
module SWIG
  class TYPE_p_bro_record   
    include Broccoli_ext
    
    # .id is a method for all ruby objects.  Move it out of the way for records.
    alias :orig_id :id
    def id
      return method_missing(:id)
    end
    
    # Retrieve record value by name
    def method_missing(meth, *args)
      bro_record_get_named_val(self, meth.id2name)
    end

    # Retrieve record value by position
    def [](pos)
      bro_record_get_nth_val(self, pos.to_i)
    end
  end
end


module Broccoli
  class Record
    include Broccoli_ext
    attr_accessor :rec
    
    def initialize
      @rec = bro_record_new()
      # Kill the BroRecord when the ruby object is garbage collected
      ObjectSpace.define_finalizer(self, Record.create_finalizer(@rec))
    end
    
    # .id is a method for all ruby objects.  Move it out of the way for records.
    alias :orig_id :id
    def id
      return method_missing(:id)
    end
    
    # Forward any missing methods on to the actual record object
    def method_missing(meth)
      @rec.send(meth)
    end
    
    def insert(name, value, type, type_name=nil)
      value = value.rec if type == :record
      bro_record_add_val(@rec, name.to_s, [Broccoli::TYPES[type], type_name, value])
    end
    
    def insert_at(pos, value, type, type_name=nil)
      value = value.rec if type == :record
      bro_record_set_nth_val(@rec, pos, [Broccoli::TYPES[type], type_name, value])
    end
    alias :insert_at_position :insert_at
    
    private 
    
    def free
      bro_record_free(@rec)
    end
    
    # When the garbage collector comes around, 
    # make sure the C structure is freed.
    def self.create_finalizer(record)
      proc { bro_record_free(record) }
    end
  end

end