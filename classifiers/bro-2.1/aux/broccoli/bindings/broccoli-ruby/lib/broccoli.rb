require 'broccoli_ext'
require 'time'

require 'Broccoli/connection'
require 'Broccoli/event'
require 'Broccoli/record'

module Broccoli
  include Broccoli_ext
  
  TYPES = {:unknown => BRO_TYPE_UNKNOWN, # not really sure how this should be handled.
           :bool => BRO_TYPE_BOOL,
           :int => BRO_TYPE_INT,
           :count => BRO_TYPE_COUNT,
           :counter => BRO_TYPE_COUNTER,
           :double => BRO_TYPE_DOUBLE,
           :time => BRO_TYPE_TIME,
           :interval => BRO_TYPE_INTERVAL,
           :string => BRO_TYPE_STRING,
           :enum => BRO_TYPE_ENUM,
           :timer => BRO_TYPE_TIMER,
           :port => BRO_TYPE_PORT,
           :addr => BRO_TYPE_IPADDR,
           :subnet => BRO_TYPE_SUBNET,
           :record => BRO_TYPE_RECORD,
           # These are not handled by the ruby binding.
           :packet => BRO_TYPE_PACKET,
           :max => BRO_TYPE_MAX,
           # All types below are NOT handled by broccoli.
           :pattern => BRO_TYPE_PATTERN,
           :any => BRO_TYPE_ANY,
           :table => BRO_TYPE_TABLE,
           :union => BRO_TYPE_UNION,
           :list => BRO_TYPE_LIST,
           :func => BRO_TYPE_FUNC,
           :file => BRO_TYPE_FILE,
           :vector => BRO_TYPE_VECTOR,
           # TYPE_TYPE is not in broccoli.h yet.
           #:type => BRO_TYPE_TYPE,
           :error => BRO_TYPE_ERROR
          }
  
  def Broccoli.current_time_f
    Broccoli_ext::bro_util_current_time
  end

  def Broccoli.current_time
    Time.at( current_time_f() )
  end

  def Broccoli.debug_calltrace=(v)
    Broccoli_ext::bro_debug_calltrace=v
  end

  def Broccoli.debug_messages=(v)
    Broccoli_ext::bro_debug_messages=v
  end
end

class Broccoli::BroPort
  @@protocols = {0=>'ip', 1=>'icmp', 2=>'igmp', 3=>'ggp', 4=>'ipv4',
                 6=>'tcp', 7=>'st', 8=>'egp', 9=>'pigp', 10=>'rccmon',
                 11=>'nvpii', 12=>'pup', 13=>'argus', 14=>'emcon',
                 15=>'xnet', 16=>'chaos', 17=>'udp', 18=>'mux', 19=>'meas',
                 20=>'hmp', 21=>'prm', 22=>'idp', 23=>'trunk1', 24=>'trunk2',
                 25=>'leaf1', 26=>'leaf2', 27=>'rdp', 28=>'irtp', 29=>'tp',
                 30=>'blt', 31=>'nsp', 32=>'inp', 33=>'sep', 34=>'3pc',
                 35=>'idpr', 36=>'xtp', 37=>'ddp', 38=>'cmtp', 39=>'tpxx',
                 40=>'il', 41=>'ipv6', 42=>'sdrp', 43=>'routing', 
                 44=>'fragment', 45=>'idrp', 46=>'rsvp', 47=>'gre', 48=>'mhrp',
                 49=>'bha', 50=>'esp', 51=>'ah', 52=>'inlsp', 53=>'swipe', 
                 54=>'nhrp', 58=>'icmpv6', 59=>'nonext', 60=>'dstopts',
                 61=>'ahip', 62=>'cftp', 63=>'hello', 64=>'satexpak', 
                 65=>'kryptolan', 66=>'rvd', 67=>'ippc', 68=>'adfs', 
                 69=>'satmon', 70=>'visa', 71=>'ipcv', 72=>'cpnx', 73=>'cphb',
                 74=>'wsn', 75=>'pvp', 76=>'brsatmon', 77=>'nd', 78=>'wbmon',
                 79=>'wbexpak', 80=>'eon', 81=>'vmtp', 82=>'svmtp', 
                 83=>'vines', 84=>'ttp', 85=>'igp', 86=>'dgp', 87=>'tcf', 
                 88=>'igrp', 89=>'ospfigp', 90=>'srpc', 91=>'larp', 92=>'mtp',
                 93=>'ax25', 94=>'ipeip', 95=>'micp', 96=>'sccsp', 
                 97=>'etherip', 98=>'encap', 99=>'apes', 100=>'gmtp', 
                 103=>'pim', 108=>'ipcomp', 113=>'pgm', 254=>'divert', 
                 255=>'raw'}
  def to_s
    #"#{port_num}/#{@@protocols[port_proto]}"
    port_num.to_s
  end
end
