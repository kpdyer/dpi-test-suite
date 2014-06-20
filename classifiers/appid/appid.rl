/* -*- c -*-
 *
 * Application ID library
 *
 * Copyright (c) 2005-2007 Arbor Networks, Inc.
 *
 * $Id: appid.rl 13 2007-07-03 23:21:07Z jon.oberheide $
 */

#include <inttypes.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* XXX - skip netinet/in.h */
#define IPPROTO_TCP	6
#define IPPROTO_UDP	17

#include "appid.h"

#define APPID_DEBUG 1
int appid_debug = 0;
#if APPID_DEBUG
/* porky array, only for debug: */
int appid_match_conflict[MAX_APPID][MAX_APPID];
#endif

struct appid_default {
	int cs;
};
struct appid_any8 {
	int cs;
};
struct appid_any4 {
	int cs;
};
struct appid_any16 {
	int cs;
};
struct appid_any {
	int cs;
};

struct appid_dns {
	int	cs;
	int	top, stack[2];  /* DNS ragel call stack is two deep */
	uint32_t len;
};

struct appid {
	        struct appid_dns	appid_dns;
	        struct appid_default	appid_default;
	        struct appid_any8	appid_any8;
	        struct appid_any4	appid_any4;
	        struct appid_any16	appid_any16;
	        struct appid_any	appid_any;
		/*
	 * state machine management - some must persist on back to
	 * back calls to appid_process - application/protocol/quality
	 * of match need to be saved so that state machines can see if
	 * they should update the match when their quality is higher
	 * than existing match.
	 */
	int		application;    // layer 7 application - e.g. rx, soap or xmlrpc
	int             confidence;
	uint8_t		ip_protocol;    // TCP/IP layer 3 protocol: 0->UDP, TCP otherwise
	uint8_t		match_count;      // 0-> no match, 1->no recognized ambiguity, otherwise ambiguous
	uint8_t		all_machines_rejected;
	size_t          payload_offset;     // help find offset into stream
	size_t          match_payload;      // offset into payload at last match
	int             more_payload_coming;
};

void 
appid_dump_match_conflict(void)
{
#if APPID_DEBUG
    int i, j;
    for(i = 0; i < MAX_APPID; i++) {
        for(j = 0; j < MAX_APPID; j++) {
            if (appid_match_conflict[i][j] > 0) {
                printf("%s overrides %s %d times.\n",
                    appid_app_to_name(i),
                    appid_app_to_name(j),
                    appid_match_conflict[i][j]);
            }
        }
    }
#else
    printf("appid_dump_match_conflict called, but needs #define APPID_DEBUG 1 to be useful.\n");
#endif
}


%%{
	machine appid_dns;

	# Alphabet is 0 to 255
	alphtype unsigned char;

	# Ragel
        dns_consume_length :=
    any*
	${
		fsm->len--;
		if (fsm->len == 0)
			fret;
	 }
	;
dns_label =
    (0x01..0x3f)		# Length
	@{ 
		fsm->len = fc; 
		fcall dns_consume_length; 
	 };
dns_pointer = ((0xc0..0xff) any);
dns_name = dns_label* (0 | dns_pointer);
dns_type = # does not include OPT (41) or NB (32)
    ((0 (1..31 | 33..40 | 42..48 | 100..103 | 249..255)) |
    (0x80 (0x00 | 0x01)));
dns_class = (0 (1 | 3 | 4 | 254 | 255));
dns_q =
    dns_name
    dns_type
    dns_class
    ;
dns_consume_q :=
    dns_q @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 25;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } @{ fret; }
    ;
dns_rr_nonopt = 
    dns_name
    dns_type
    dns_class
    #any{4}		# TTL
    #any{2}		# RDLENGTH
    #any*		# RDDATA
    ;
dns_rr_opt =
    0 			# Name: Root
    (0 41)		# Type: OPT (41)
    #any{2}		# "Class": Senders UDP payload size
    #any{4}		# "TTL": Extended RCODE and flags
    #any{2}		# "RDLENGTH": Describes RDATA
    #any{2}		# Option code (cannot find assignments)
    #any{2}		# Option length
    #any*		# Option
    ;
dns_rr = dns_rr_nonopt | dns_rr_opt ;
dns_consume_rr :=
    dns_rr @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 25;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } @{ fret; }
    ;
dns =
    #any{2}?            # XXX - DNS over TCP needs this, but it won't
                        # work currently because you can't use '?' (which
                        # creates a new branch) before an fcall (which modifies
                        # the state) -- see dhelder@ for more detail :)
    any{2}		# ID
    ((0x00 .. 0x17) |   # QR 0, Opcode 0-2, AA,TC,RD=*
     (0x20 .. 0x2f) |   # QR 0, Opcode 4,5, AA,TC,RD=*
     (0x80 .. 0x97) |   # QR 1, Opcode 0-2, AA,TC,RD=*
     (0xa0 .. 0xaf))    # QR 1, Opcode 4,5, AA,TC,RD=*
    ((0x00 .. 0x0a) |   # RA 0, AD 0, CD 0, Rcode 0-10
     (0x10 .. 0x1a) |   # RA 0, AD 0, CD 1
     (0x20 .. 0x2a) |   # RA 0, AD 1, CD 0
     (0x30 .. 0x3a) |   # RA 0, AD 1, CD 1
     (0x80 .. 0x8a) |   # RA 1, AD 0, CD 0
     (0x90 .. 0x9a) |   # RA 1, AD 0, CD 1
     (0xa0 .. 0xaa) |   # RA 1, AD 1, CD 0
     (0xb0 .. 0xba))    # RA 1, AD 1, CD 1
    #
    # Next four fields are:
    #   QDCOUNT	    Question count
    #   ANCOUNT	    Answer RR count
    #   NSCOUNT	    Authority RR count
    #   ARCOUNT	    Additional RR count
    #
    # Match on no questions or RRs or at least one question or
    # RR.  Specifically, parse the name, type, and class.  Type
    # and class are highly selective compared to the header.
    #
    # A full parse is possible, but much more complex.  If
    # the truncation flag is set, a full parse my not succeed
    # anyway.
    (
     # QDCOUNT=0, RRCOUNTs=0, no trailing garbage.
     # Otherwise we'd match all-zero packets
     # (e.g. NTP-v4-OpenBSD-stratum-0.pcap).  Note that Bind
     # would allow this.
     #
     # Note the "</" action - this is "any action going to the EOF
     # state".  This assumes that the payload length is all that we're
     # seeing of this stream.  Probably a reasonable assumption, given
     # how short it is.
     #
     # This is really a corner case: if we spoonfeed appid_process payloads
     # 1 byte at a time (even if the caller will be sending more payload),
     # then this will match any payload such as "any any 0{8}"
     # If we reject payloads fed 1 byte at a time, we can't detect the empty
     # DNS case, where the total payload is "any any 0{8}" when the payload
     # is sent 1 byte at a time.
     #
     # So, for the time being, I've put a custom match condition here which
     # rejects the 1 byte at a time payload, which really means this never matches
     # in the 1 byte at a time case.  It will, however, match when the payload
     # length is 10 bytes (ie hopefully the 'normal' UDP/DNS empty query case).
     #
     (0{8}) </ { if (!a->more_payload_coming) { { 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 25;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } } } |
     #
     # QDCOUNT=1+, followed by a question
    ((any{2} - (0 0)) any{6} @{ fcall dns_consume_q; }
      any*) |
     #
     # QDCOUNT=0, RRCOUNTs=1+, followed by RR
     ((0 0) (any{6} - 0{6})  @{fcall dns_consume_rr; }
      any*)
    )
    ;

	apps = dns ;
	main := apps;
}%%

%% write data;

static int
appid_dns_execute(
	struct appid *a,
	struct appid_dns *fsm,
	unsigned char		ip_protocol,
	unsigned short		src_ip_port,
	unsigned short		dst_ip_port,
	const unsigned char    *payload,
	int			payload_length)
{
	const unsigned char *p = payload;
	const unsigned char *pe = payload + payload_length;

%% access fsm->;
%% write exec;
/*
 * ragel doc section 5.4.4 states that 'write eof' is of no cost
 * if no machines use the EOF transitions.  DNS does, so
 * we include this in all
 */
%% write eof;

	if (fsm->cs == appid_dns_error)
		return (-1);
	else if (fsm->cs >= appid_dns_first_final)
		return (1);
	return (0);
}


%%{
	machine appid_default;

	# Alphabet is 0 to 255
	alphtype unsigned char;

	# Ragel
        dcerpc_version =
    5 0		# Version: 5.0
    ;
dcerpc_flags_dr_frag_auth_callid =
    any		# PFC flags (Section 12.6.3.1)
    (0x00 | 0x01 | 0x10 | 0x11)	# DR: Integer/character [*]
    (0 .. 3)	# DR: Floating point (0..3 assigned)
    0 0		# DR: Reserved
    any{2}	# Fragment length
    any{2}	# Auth length
    any{4}	# Call identifier
    ;
dcerpc_non_bind =
    dcerpc_version
    ((0 .. 19) - 11)	# Packet type (0 .. 19 assigned, Bind (11) below)
    dcerpc_flags_dr_frag_auth_callid
    #any*		# ...
    ;
dcerpc_uuid_mapi = # a4f1db00-ca47-1067-b41f-00dd010662da
    0x00 0xdb 0xf1 0xa4			# Time low
    0x47 0xca 				# Time mid
    0x67 0x10 				# Time high and version
    0xb3 0x1f				# Clock seq, clock seq low
    0x00 0xdd 0x01 0x06 0x62 0xda	# Node
    ;
dcerpc_bind_extra = 
    any{2}	# Max transmit frag size
    any{2}	# Max receive frag size
    any{4}	# Assoc group ID
    # p_cont_list:
     any	# Number of items in list
     0 0 0	# Reserved
     # p_cont_elem+:  # One or more context elements
      any{2}	# Context id
      any	# Number of items
      0		# Reserved
      # p_syntax_id:
       #any{16}	# UUID
       #any{4}	# Interface version
    ;
dcerpc_bind_pre_uuid =
    dcerpc_version
    11					# Packet type: Bind (11)
    dcerpc_flags_dr_frag_auth_callid
    dcerpc_bind_extra
    ;
dcerpc_bind = 
    dcerpc_bind_pre_uuid
    (any{16} - dcerpc_uuid_mapi)	# UUID
    ;
dcerpc = 
    (dcerpc_non_bind | dcerpc_bind) 
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 23;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any* 
    ;

asn1_length = 
    (0x00..0x7f)  | # Short form
    (0x81 any{1}) | # Long form up to 4 bytes
    (0x82 any{2}) |
    (0x83 any{3}) |
    (0x84 any{4})
    ;
kerberos_msg_tag0 = 
    (		    # CHOICE
     0x6b |	    # AS-REP (11)
     0x6d |	    # TGS-REP (13)
     0x6e |	    # AP-REQ (14)
     0x6f |	    # AP-REP (15)
     0x74 |	    # KRB-SAFE (20)
     0x75 |	    # KRB-PRIV (21)
     0x76 |	    # KRB-CRED (22)
     0x7e	    # KRB-ERROR (30)
    )
    asn1_length     # CHOICE length
    0x30	    # SEQUENCE
    asn1_length     # SEQUENCE length
    0xa0 3  2 1 5   # Protocol version INTEGER 5 [0]
    0xa1 3  2 1     # Message type [1]
      (11 | 13..15 | 20..22 | 30)
    ;
kerberos_msg_tag1 = 
    (		    # CHOICE
     0x6a |	    # AS-REQ (10)
     0x6c	    # TGS-REQ (12)
    )
    asn1_length     # CHOICE length
    0x30	    # SEQUENCE
    asn1_length     # SEQUENCE length
    0xa1 3  2 1 5   # Protocol version INTEGER 5 [0]
    0xa2 3  2 1     # Message type [1]
      (10 | 12)
    ;
kerberos_ticket = 
    0x61	    # CHOICE: TICKET (1)
    asn1_length	    # CHOICE length
    0x30	    # SEQUENCE
    asn1_length     # SEQUENCE length
    0xa0 3  2 1 5   # Ticket version INTEGER 5 [0]
    0xa1 9 	    # Realm GeneralString [1]
    ;

nick =
    /NICK/i
    " "+ [^ \r\n]+ ( " "+ digit+ )? " "* [\r\n]+;
user =
    /USER/i
    " "+ [^ \r\n]+ " "+ [^ \r\n]+ " "+ [^ \r\n]+ " "+ any+ [\r\n]+;
irc = ( user nick | nick user ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 43;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

ssdp = ( "M-SEARCH" | "NOTIFY" ) " * HTTP/1.1\r\n" @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 101;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

mute_key_exchange =
    ( "PublicKey: "i | "AESKey: " )
    xdigit* :>>
    ( "\nEndPublicKey\n"i | "\nEndAESKey\n" )
    ;
mute = mute_key_exchange @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 56;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

teamspeak = 0xf4 0xbe 0x03 @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 109;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

netflow1_header =
    0 1                 # netflow v1
    0 1..24             # num flow records (max 24)
    any{4}              # system uptime
    any{4}              # epoch seconds
    any{4}              # epoch nanoseconds
    ;
netflow1_record =
    any{4}              # src ip
    any{4}              # dst ip
    any{4}              # next hop ip
    any{2}              # snmp index of input intf
    any{2}              # snmp index of output intf
    any{4}              # packets in flow
    any{4}              # total layer3 bytes
    any{4}              # sysuptime at flow start
    any{4}              # sysuptime at flow end
    any{2}              # src port
    any{2}              # dst port
    0x00 0x00           # unused pad
    any                 # proto type
    any                 # ip tos
    any                 # tcp flags
    0x00{7}             # unused pad
    ;
netflow1 = netflow1_header netflow1_record;
netflow5_header =
    0 5                 # netflow v5
    0 1..30             # num flow records (max 30)
    any{4}              # system uptime
    any{4}              # epoch seconds
    any{4}              # epoch nanoseconds
    any{4}              # total flows
    (0 | 1)             # engine type (0 for RP, 1 for VIP/LC)
    any                 # engine slot number
    any{2}              # sample mode/interval
    ;
netflow5_record =
    any{4}              # src ip
    any{4}              # dst ip
    any{4}              # next hop ip
    any{2}              # snmp index of input intf
    any{2}              # snmp index of output intf
    any{4}              # packets in flow
    any{4}              # total layer3 bytes
    any{4}              # sysuptime at flow start
    any{4}              # sysuptime at flow end
    any{2}              # src port
    any{2}              # dst port
    0x00                # unused pad
    any                 # tcp flags
    any                 # proto type
    any                 # ip tos
    any{2}              # src as
    any{2}              # dst as
    any                 # src prefix mask
    any                 # dst prefix mask
    0x00 0x00           # unused pad
    ;
netflow5 = netflow5_header netflow5_record;
netflow7_header =
    0 7                 # netflow v7
    0 1..27             # num flow records (max 27)
    any{4}              # system uptime
    any{4}              # epoch seconds
    any{4}              # epoch nanoseconds
    any{4}              # total flows
    0x00{4}             # unused pad
    ;
netflow7_record =
    any{4}              # src ip
    any{4}              # dst ip
    any{4}              # next hop ip
    any{2}              # snmp index of input intf
    any{2}              # snmp index of output intf
    any{4}              # packets in flow
    any{4}              # total layer3 bytes
    any{4}              # sysuptime at flow start
    any{4}              # sysuptime at flow end
    any{2}              # src port
    any{2}              # dst port
    any                 # flags
    any                 # tcp flags
    any                 # proto type
    any                 # ip tos
    any{2}              # src as
    any{2}              # dst as
    any                 # src prefix mask
    any                 # dst prefix mask
    any{2}              # flags
    any{4}              # router ip
    ;
netflow7 = netflow7_header netflow7_record;
netflow8_header =
    0 8                 # netflow v8
    0 1..51             # num flow records (max 51)
    any{4}              # system uptime
    any{4}              # epoch seconds
    any{4}              # epoch nanoseconds
    any{4}              # total flows
    any                 # engine type
    any                 # engine slot number
    any                 # aggregation method
    any                 # aggregation export
    0x00{4}             # unused pad
    ;
netflow8 = netflow8_header;
netflow9_header = 
    0 9                 # netflow v9
    0..6 any		# num flow records
    any{4}              # system uptime
    any{4}              # epoch seconds
    any{4}              # sequence number
    any{4}              # source id
    ;
netflow9 = netflow9_header;
netflow = ( netflow1 | netflow5 | netflow7 | netflow8 | netflow9 ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 60;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

xml_ws = (' ' | '\r' | '\n' | '\t')+;
xml_eq = xml_ws? '=' xml_ws?;
xml_num = [0-9] '.' [0-9];
xml_enc = [A-Za-z] ([A-Za-z0-9._] | '-')*;
xml_enc_decl = xml_ws 'encoding' xml_eq ('"' xml_enc '"' | "'" xml_enc "'" );
xml_version = xml_ws 'version' xml_eq ("'" xml_num "'" | '"' xml_num '"');
xml_text_decl = '<?xml' xml_version xml_enc_decl? xml_ws? '?>';
xml = "";

nntp = ("200" | "201") space+ [^\r\n]* [\r\n]+ @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 63;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

icy_server_response = 
  "ICY"i " "		# Version
  digit{3} " "  	# Status code
  [^\r\n]+ [\r\n]+	# Reason phrase
  ;
icy = 
    icy_server_response
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 38;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
    ;

msn_notification_cnxn =
    "VER "			# VER command
    digit+			# Transaction ID
    ( " " alnum+ )*		# Any number of protocol versions
    ( " MSNP" digit+ )		# Must have at least one MSN protocol listed
    ( " " alnum+ )*		# Any number of protocol versions
    0xd 0xa;			# \r\n
msn_switchboard_cnxn =
    ( "USR " | "ANS " )		# USR (request) or ANS (answer) command
    digit+			# Transaction ID
    " "				# Space
    [^ \r\n]+			# Account name
    " "				# Space
    [^ \r\n]+			# Authentication string
    ( " " [^ \r\n]+ )?		# Switchboard session ID (for "answer" only)
    0xd 0xa;			# \r\n
msn_webcam =
    "recipientid="i alnum+	# Recipient ID
    "&sessionid="i alnum+	# Session ID
    0xd 0xa 0xd 0xa;		# \r\n\r\n
msn =
    ( msn_notification_cnxn | msn_switchboard_cnxn | msn_webcam ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 55;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

rtsp = "RTSP/1.0 " digit{3} [^\r\n]* 0xd 0xa @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 90;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

edonkey_tcp =
    (0xe3 | 0xc5 | 0xd4)			# Protocol
    (((any - 0) 0) | (any (any - 0))) 0 0	# Packet data length
    0x01					# Hello server
    ;
edonkey = edonkey_tcp @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 26;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

groupwise_login = 
    "POST /login" [^ ]+ " HTTP/1." digit "\r\n"		# HTTP/1.x POST
    (((any - [\r])+ "\r\n")*) :>> 			# additional HTTP headers
    ( "\r\n\r\n"					# end of HTTP header
      "&"? "tag=NM_A_SZ_USERID"i  )			# POST data
    ;
groupwise = groupwise_login @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 33;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

vnc = 
    "RFB " digit digit digit "." digit digit digit 0xa @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 113;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

svn_server_response = "( success ( 1 2 ("i;
svn = svn_server_response @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 105;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

xmpp_new_session = xml_text_decl? xml_ws? "<stream:stream";
xmpp = xmpp_new_session @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 117;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

ldap =
  0x30 any+	        # SEQUENCE
  0x02 			# INTEGER: Message ID (0 .. 2^31-1)
    ((1 any{1}) |       #   Length and contents
     (2 any{2}) |
     (3 any{3}) |
     (4 any{4}))
  (			# CHOICE
   0x60 | 		# BindRequest (0)
   0x61 |	        # BindResponse (1)
   0x62 | 		# UnbindReques (2)
   0x63 | 		# SearchRequest (3)
   0x64 | 		# SearchResultEntry (4)
   0x65 | 		# SearchResutlDone (5)
   0x71 | 		# SearchResultReference (17) (LDAP v3)
   0x66 | 		# ModifyRequest (6)
   0x67 | 		# ModifyResponse (7)
   0x68 | 		# AddRequest (8)
   0x69 | 		# AddResponse (9)
   0x6a | 		# DelRequest (10)
   0x6b | 		# DelResponse (11)
   0x6c | 		# ModifyDNRequest (12)
   0x6d | 		# ModifyDNResponse (13)
   0x6e | 		# CompareRequest (14)
   0x6f | 		# CompareResponse (15)
   0x70 | 		# AbandonRequest (16)
   0x77 | 		# ExtendedRequest (23) (LDAP v3)
   0x78 		# ExtendedResponse (24) (LDAP v3)
  ) # All choices are constructed applications (bits 6 and 7 set)
  @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 47;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
  ;

http_response_status_line =
    "HTTP/" digit+ "." digit+ " "	# Version
    digit{3}				# Status code 
    [^\r\n]+? [\r\n]+			# Reason phrase
    ;
http = 
    http_response_status_line
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 35;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
    ;

ripv1_entry = 
    0 2				# address family (2=AF_INET)
    0 0				# unused
    any{4}			# ipv4 address
    0 0 0 0			# unused
    0 0 0 0			# unused
    0 0 0 1..16			# metric (1..15=cost, 16=infinity)
    ;
ripv2_entry = 
    0 2				# address family (2=AF_INET)
    any any			# route tag
    any{4}			# ipv4 address
    any{4}			# subnet mask
    any{4}			# next hop
    0 0 0 1..16			# metric (1..15=cost, 16=infinity)
    ;
ripv1_message = 
    (1 | 2)			# command (1=request, 2=response)
    1				# version
    0 0				# unused
    ripv1_entry			# ripv1 entry
    ;
ripv2_message = 
    (1 | 2)			# command (1=request, 2=response)
    2				# version
    0 0				# unused
    ripv2_entry			# ripv2 entry
    ;
rip = ( ripv1_message | ripv2_message ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 85;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

zephyr_header = "ZEPH" digit "." digit;
zephyr = zephyr_header @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 119;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

cups_browsing = 
    xdigit{1,5} " "		# printer type
    ( "3" | "4" | "5" ) " "	# printer state (idle, processing, stopped)
    "ipp://"
    ;
cups = cups_browsing @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 20;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

netbios_ss_req =
    0x81	       # Type: Session Request (0x81)
    (0x00 | 0xf0)      # Flags (7 is E, 0-6 reserved)
    any{2}	       # Length
    (any - 0)+ 0       # Called name
    (any - 0)+ 0       # Calling name
    ;
netbios_ss_msg_hdr =
    0x00	       # Type: Session Message (0x00)
    (0x00 | 0x01)      # Flags (7 is E, 0-6 reserved)
    any{2}	       # Length
    ;
netbios_ds_msg_hdr =
    (0x10 .. 0x12)     # Type: Direct Unique or Group, or Broadcast
    (0x00 .. 0x0f)     # Flags (4-7 assigned, 0-3 reserved)
    any{2}	       # DGM ID
    any{4}	       # Source IP
    any{2}	       # Source Port
    any{2}	       # Length
    any{2}	       # Packet offset
    32 [A-P]{32} 0     # Source name
    32 [A-P]{32} 0     # Destination name
    ;
smb =
    ((netbios_ss_req?       # NetBIOS Session Service: Request (optional)
      netbios_ss_msg_hdr) | # NetBIOS Session Service: Message
      netbios_ds_msg_hdr)   # NetBIOS Datagram Service: Data
    0xff "SMB"	       # ID
    (0x25 | 0x72)      # Command: Trans (0x25) or Negotiate protocol (0x72)
    0 0 0 0	       # Status: Success
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 96;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
    ;

syslog = 
    "<" 
    ( (digit) |			   # 0-9
      (digit digit) |		   # 10-99
      ("1" ("0" .. "8") digit) |   # 100-189
      ("1" "9" ("0" .. "3")) )	   # 190-193
    ">"
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 106;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

gnutella_control = "GNUTELLA CONNECT";
gnutella_data = ("GET /uri-res/N2R?urn:sha1:" | "GET /get/" digit{1,10} "/");
gnutella2_udp = "GND" 0x00..0x03;
gnutella = ( gnutella_control | gnutella_data | gnutella2_udp ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 32;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

quake1_conn_request = 
    0x80 0x00			# control message type
    0x00 0x0c			# length of message (12)
    0x01			# connection request type
    "QUAKE"i 0x00		# game name string
    0x03			# protocol version
    ;
quake1 = quake1_conn_request @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 79;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

rsync = "@RSYNCD: " @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 88;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

postgresql_ssl_connection =
    0x00 0x00 0x00 0x08			# message length
    0x04 0xd2				# magic number (1234)
    0x16 0x2f				# magic number (5679)
    ;
postgresql = postgresql_ssl_connection @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 76;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

pop3_server = 
    ("+OK "i | "-ERR "i)	# +OK or -ERR
    [^\r\n]+ [\r\n]+		# Rest of line
    ;
pop3_client =
    ("USER "i [^ ]+ [\r\n]+
     (("PASS "i [^ \r\n]+ [\r\n]+) | ("QUIT"i [\r\n]+))) |
    ("APOP "i [^ \r\n]+ " " xdigit{16} [\r\n]+)
    ;
pop = (pop3_server | pop3_client) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 75;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

mgcp_eol		= ( "\r\n" | "\n" );
mgcp_wsp		= ( " " | "\t" );
mgcp_verb		= ( "EPCF"i | "CRCX"i | "MDCX"i | "DLCX"i | "RQNT"i |
			    "NTFY"i | "AUEP"i | "AUCX"i | "RSIP"i );
mgcp_version		= ( "MGCP 1.0" );
mgcp_transid		= digit{1,9};
mgcp_command		= mgcp_verb mgcp_wsp{1,} mgcp_transid mgcp_wsp{1,}
			  any* :>> mgcp_version;
mgcp			= mgcp_command @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 53;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

fasttrack_transfer =
    ("GET /.hash=") |
    ("GET /" any+ 0xd 0xa "X-Kazaa") |
    ("GIVE ")
    ;
fasttrack_udp_ping =
    0x27					# Message type
    any{4}					# Minimum encryption type
    0x80					# Unknown
    "KaZaA" 0					# Zero terminated network name
    ;
fasttrack_udp_pong =
    0x28					# Message type
    any{4}					# Minimum encryption type
    0 any{5}					# Unknown
    "KaZaA" 0					# Zero terminated network name
    ;
fasttrack = (fasttrack_udp_ping | fasttrack_udp_pong | fasttrack_transfer)
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 28;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

rtp = empty;

megaco_eol		= ("\r\n" | "\n");
megaco_wsp		= (" " | "\t");
megaco_lwsp		= (megaco_wsp | megaco_eol)*;
megaco_equal		= (megaco_lwsp "=" megaco_lwsp);
megaco_sep		= ((megaco_wsp | megaco_eol) megaco_lwsp);
megaco_authtoken	= ("Authentication"i | "AU"i);
megaco_megacoptoken	= ("MEGACO"i | "!");
megaco_seqnum		= ("0x" xdigit{8});
megaco_securityindex	= ("0x" xdigit{8});
megaco_authdata		= ("0x" xdigit{24,64});
megaco_authheader	= megaco_authtoken megaco_equal megaco_securityindex ":" megaco_seqnum ":" megaco_authdata;
megaco_header		= megaco_megacoptoken "/1" megaco_sep;
megaco_message		= (megaco_authheader megaco_sep)? megaco_header;
megaco			= megaco_message @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 52;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

ntp2 = 
    (0x00 | 0x01 | 0x02 | 0x03 | 0x04 |  # leap year 0
     0x40 | 0x41 | 0x42 | 0x43 | 0x44 |  # leap year 1
     0x80 | 0x81 | 0x02 | 0x83 | 0x84 |  # leap year 2
     0xc0 | 0xc1 | 0xc2 | 0xc3 | 0xc4)   # leap year 3
    (0 .. 4)			         # status
    #any{46}			         # other
    ;
ntp4 = 
    (0x19 | 0x1a | 0x1b | 0x1c | 0x1d | # LY 0, Version 3
     0x21 | 0x22 | 0x23 | 0x24 | 0x25 | # LY 0, Version 4
     0x59 | 0x5a | 0x5b | 0x5c | 0x5d | # LY 1, Version 3
     0x61 | 0x62 | 0x63 | 0x64 | 0x65 | # LY 1, Version 4
     0x99 | 0x9a | 0x9b | 0x9c | 0x9d | # LY 2, Version 3
     0xa1 | 0xa2 | 0xa3 | 0xa4 | 0xa5 | # LY 2, Version 3
     0xd9 | 0xda | 0xdb | 0xdc | 0xdd | # LY 3, Version 3
     0xe1 | 0xe2 | 0xe3 | 0xe4 | 0xe5)  # LY 3, Version 3
    (0 .. 15)			        # stratum
    #any{46}				# other
    #(any{20})?				# optional
    ;
ntp = ntp2 | ntp4 @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 64;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

quake3_commands =
    ( "getinfo"i | "getchallenge"i | "getchallengeresponse"i | "getstatus"i |
      "getmotd"i | "getmotdresponse"i | "getservers"i | "getipauthorize"i |
      "getkeyauthorize"i | "info"i | "rcon"i | "connect"i | "connectresponse"i );
quake3 = 0xff{4} quake3_commands @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 80;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;


gg_welcome = 
    0x01 0x00 0x00 0x00		# welcome message type
    0x04 0x00 0x00 0x00		# welcome message length
    any any any any		# server seed
    ;
gadugadu = gg_welcome @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 30;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

ares_client_connect = 
    0x03 0x00			# length of client syn
    0x5a			# client syn command
    0x06 0x06 0x05		# protocol version
    ;
ares = ares_client_connect @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 13;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

soap_post = 
   "POST " [^ ]+ " HTTP/1.1\r\n"	# HTTP/1.1 POST
   (((any - [\r])+ "\r\n")*) :>>	# additional HTTP headers
   ( "Content-Type:"i [ \t]*		# application/soap+xml
     "application/soap+xml"i )
   ;
soap_response =
   "HTTP/1.1 200 OK\r\n"		# HTTP/1.1 OK response
   "Content-Type:"i [ \t]*		# application/soap+xml
   "application/soap+xml"i
   ;
soap = ( soap_post | soap_response ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 99;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

ventrilo_connect =
    0x00 any			# packet length (assume < 256)
    any				# unknown
    0x56 0x24 0xcf		# magic cookie
    ;
ventrilo = ventrilo_connect @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 112;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

ipp = 
   "POST " [^ ]+ " HTTP/1.1\r\n"     # All IPP is POST
   (((any - [\r])+ "\r\n")*) :>>     # Header lines
   ("Content-Type:"i [ \t]* 	     # Content-Type: application/ipp
    "application/ipp\r\n"i)
   @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 41;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
   ;

ssh = "SSH-" digit+ "." digit+ @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 102;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any* ;

kerberos_udp = 
    (kerberos_msg_tag0 | kerberos_msg_tag1 | kerberos_ticket)
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 45;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
    ;

tpkt_header =
    0x03		# TPKT version 3
    0x00		# Reserved field
    any any		# TPKT packet length
    ;
h323_call_setup = 
    0x08				# Protocol discriminator (Q.931)
    (0x00) |				# Call reference value
    (0x01 any{1}) |			# Varies between 0-15 bytes
    (0x02 any{2}) |			# XXX refactor using Semantic Conditions
    (0x03 any{3}) |
    (0x04 any{4}) |
    (0x05 any{5}) |
    (0x06 any{6}) |
    (0x07 any{7}) |
    (0x08 any{8}) |
    (0x09 any{9}) |
    (0x0a any{10}) |
    (0x0b any{11}) |
    (0x0c any{12}) |
    (0x0d any{13}) |
    (0x0e any{14}) |
    (0x0f any{15}) 
    (0x05 | 0x02)			# Message type (Setup, Call Proceding)
    ;
h323 = tpkt_header h323_call_setup @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 34;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

smtp_server_ready =
    ("220") |			# 220 ("Service ready")
    ("554")			# 554 ("Trans. failed")
    [^\r\n]* [\r\n]+;		# Anything followed by CRLF
smtp_client_helo =
    (/HELO/i |			# Must be issued before any mail transaction
     /EHLO/i)
    [^\r\n]* [\r\n]+;		# Anything followed by newline
smtp = (smtp_server_ready | smtp_client_helo) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 97;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

x11_client_request_le = 
    0x6c			# byte order
    0x00			# unused
    0x0b 0x00			# protocol-major-version (11)
    0x00 0x00			# protocol-minor-version (0)
    any any			# authorization-protocol-name-length
    any any			# authorization-protocol-data-length
    0x00 0x00			# unused
    ;
x11_client_request_be =
    0x42			# byte order
    0x00			# unused
    0x00 0x0b			# protocol-major-version (11)
    0x00 0x00			# protocol-minor-version (0)
    any any			# authorization-protocol-name-length
    any any			# authorization-protocol-data-length
    0x00 0x00			# unused
    ;
x11 = ( x11_client_request_le | x11_client_request_be ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 114;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

imap_text = [^\r\n\0] ;
imap_tag = [^ +(){%*"'\\\r\n\0]+; # Also excludes "CTL"?
server_greeting =
    "* "
    ("OK"i | "PREAUTH"i | "BYE"i)
    imap_text* "\r\n"
    ;
client_first_command =
   imap_tag " "
   (("NOOP"i |		# IMAP command without arguments
     "CAPABILITY"i |
     "STARTTLS"i) |
    ("LOGIN"i |		# IMAP command with arguments
     "AUTHENTICATE"i |
     "LOGOUT"i |
     "SELECT"i |
     "EXAMINE"i)
     " " imap_text*)
   "\r\n"
   ;
imap =
    server_greeting
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 40;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
    ;

cvs_client_connect = "BEGIN " ( "AUTH" | "VERIFICATION" | "GSSAPI" ) " REQUEST\n";
cvs_server_response = ( "I LOVE YOU\n" | "I HATE YOU\n" );
cvs = ( cvs_client_connect | cvs_server_response ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 21;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

lpd_space = " \t\v\f"+ ;     # space, tab, vertical tab, form-feed
lpd_word = (any - [\0\n])+;  # RFC says ASCII, but be less strict
lpd_receive_job_subcommand = 
  (0x01 "\n") |			    # Abort
  (0x02				    # Receive control file
    digit+ lpd_space		    #   data length
    "cfA" digit{3} lpd_word "\n") | #   file name
   #any*			    #   data (see Section 6)
  (0x03 			    # Receive data file
    digit+ lpd_space		    #   data length
    "dfA" digit{3} lpd_word "\n")   #   file name
   #any*			    #   data (arbitrary)
  ;
lpd_request = 
  (0x01 lpd_word "\n") |	    # Print any waiting jobs
  (0x02 lpd_word "\n"  	            # Receive a printer job
    lpd_receive_job_subcommand) |
  (0x03 lpd_word           	    # Send queue state (short)
    (lpd_space lpd_word)? "\n") |   #   user names, job numbers
  (0x04 lpd_word	    	    # Send queue state (long)
    (lpd_space lpd_word)? "\n") |   #   user names, job numbers
  (0x05 lpd_word lpd_space	    # Remove jobs
    lpd_word lpd_space		    #   agent
    lpd_word "\n")		    #   name
  ; 
lpd = 
  lpd_request
  @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 49;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

peer_connection =
    0x13
    "BitTorrent protocol"
    ;
tracker_connection = 
    "GET /announce?"  
    ( "info_hash" |
      "peer_id" |
      "ip" |
      "port" |
      "uploaded" |
      "downloaded" |
      "left" |
      "event" )
    "=";
bittorrent = ( peer_connection | tracker_connection ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 15;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

slp_msg = 
    0x02				# version
    1..11				# function id
    any any any				# message length
    (0x20 | 0x40 | 0x80) 0x00		# flags
    any any any				# extension offset
    any any				# xid
    any any				# language tag length
    any* :>>
    "service:"i
    ;
slp = slp_msg @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 95;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

itot_header =
    0x03			# Protocol version number
    0x00			# Reserved
    any any			# Packet length
    ;
rdp_cr = 
    any				# header length
    0xe0			# connection request
    any any			# dst ref
    any any			# src ref
    any				# class
    "Cookie: mstshash="i	# auth cookie
    ;
rdp_cc = 
    any				# header length
    0xd0			# connection confirm
    any any			# dst ref
    any any			# src ref
    any				# class
    ;
rdp_dt = 
    any				# header length
    0xf0			# data transfer
    0x80			# eot
    ;
rdp =
    itot_header 
    (rdp_cr |			# connection request
     rdp_cc |			# connection confirm
     rdp_dt)			# data transfer
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 82;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
  ;

bgp4 =
    0xff{16}				# Marker (must be all 1's for an OPEN message)
    ((0x00 0x1d..0xff) |		# Length (between 29 and 4096)
    (0x01..0x10 any))
    1					# Type (1 = OPEN message)
    4					# Version = 4
    any{9}				# My AS, HoldTime, BGP ID, optional params len
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 14;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;
bgp = bgp4;

nmdc_commands = 
    ( "$Lock "i |
      "$Key "i |
      "$ValidateNick "i |
      "$HubName "i |
      "$ConnectToMe "i );
nmdc = nmdc_commands @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 62;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

tds_45_client_login = 
  # TDS Header
  0x02		# Type: Login (0x02)
  0x00		# Last packet indicator
  0x02 0x00	# Size: 512 bytes
  0 0		# Channel
  0		# Packet number
  0		# Window
  # TDS Login
  # any*
  # major_version, minor_version at bytes 466 and 468 (uints)
  # Don't bother matching since it would add 466+ states.
  ;
tds_457_server_login_response =
  # TDS Header
  0x04		# Type: Response
  0x01		# Last packet indicator
  any{2}	# Size
  any{2}	# Channel (can be non-0)
  1		# Packet number
  0		# Window
  # TDS Packet
  (0xaa | 	# Type: Error
   0xab |	# 	Info Message
   0xad |	# 	Login Acknowledgement
   0xe3 |	# 	Environment change
   0xe5 |	# 	Extended error message
   0xfd)	# 	Done
  # any{2}	# Length
  # any*	# Data
  # Microsoft-SQL will include the string "Microsoft SQL Server"
  # in version 4.x, and this string using wide chars in version 7.0.
  ;
tds_7_client_login = 
  # TDS Header
  0x10	 	# Type: Login (0x10)
  0x01		# Last packet indicator
  any{2}	# Size
  0 0		# Channel
  0		# Packet number
  0		# Window
  # TDS Packet
  any{4}	# Length
  0 0 0 0x70	# Version
  # any*	# Username, password, etc
  ;
tds_8_client_login =
  # TDS Header
  0x12	 	# Type: 0x12
  0x01		# Last packet indicator
  any{2}	# Size
  0 0		# Channel
  0		# Packet number
  0		# Window
  # TDS Packet
  0		# NetLib Version
  0 21		#   Offset: START_POS
  0 6		#   Length: 6
  1		# Encryption
  0 27		#   Offset: START_POS + 6
  0 1		#   Length: 1
  2 		# Instance
  0 28		#   Offset: START_POS + 6 + 1
  any{2}	#   Instance name length
  3		# Process ID
  any{2}	#   START_POS + 6 + 1 + instance name length
  0 4		#   Length: 4
  0xff		# End
  8 0 1 0x55 0 0 # Netlib Version
  0		# Encryption
  # any{N}	# Instance name
  # any{4}	# Process ID
  # any*
  ;
tds_8_server_login_response =
  # TDS Header
  0x04		# Type: Response
  0x01		# Last packet indicator
  any{2}	# Size
  0 0		# Channel (seems to be 0 with MS-SQL)
  1		# Packet number
  0		# Window
  # TDS Packet
  0		# NetLib Version
  any{2}	#   Offset: ?
  0 6		#   Length: 6
  # any*
  ;
tds = 
    (tds_45_client_login | tds_457_server_login_response |
     tds_7_client_login  | 
     tds_8_client_login  | tds_8_server_login_response)
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 108;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
    ;

daap = "GET " "daap://"i @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 22;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

citrix_dsniff =
    0x7f 0x7f 0x49 0x43
    0x41 0x00
    ;
citrix = citrix_dsniff @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 16;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

stun_attr = 
    0x00 0x03				# change-request attr type
    0x00 0x04				# attr length
    0x00 0x00 0x00 (0x04 | 0x02 | 0x00)	# change-ip/change-port
    ;
stun_request = 
    0x00 0x01				# binding request
    0x00 0x08				# request length
    any{16}				# 128-bit transaction id
    stun_attr
    ;
stun = stun_request @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 104;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

tftp =
    0 ( 1 | 2 ) (any - 0)+ 0 ( "netascii"i | "octet"i | "mail"i ) 0 @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 111;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;


rdt = empty;

corba_message =
    "GIOP"			# magic cookie
    0x01 0x00			# version (major, minor)
    (0x00 | 0x01)		# byte order (be, le)
    (0x00 | 0x01)		# message type (request, reply)
    any{4}			# message size
    ;
corba = corba_message @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 19;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

telnet = 
    (255 (251..254) any){3}     # IAC WILL/WON'T/DO/DON'T
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 110;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

ftp = "220" [^\r\n]* [\r\n]+ @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 29;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

yahoo_messenger =
    ( "YMSG"i |			# Standard header for all commands and messages
      "YPNS"i | "YHOO"i )	# Headers used by Ethereal
    				#    (http://ethereal.com/faq.html#q5.32)
    0 0..12 0 0			# 4 bytes of version, last two can safely be 0 0
    				#    Version currently goes up to 12 (0x0c)
    				#    Server messages have version == 0
    any any			# Length of message (total length - header[20 bytes])
    0x00
    ;
yahoo = yahoo_messenger @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 118;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

tacacs_plus = 
    0xc0				# Version (major = 0xc, minor = 0x0)
    (0x01 | 0x02 | 0x03)		# Type
    1					# Sequence number (first MUST be 1)
    (0x00 | 0x01 | 0x04 | 0x05)		# Flags
    any{4}				# Session ID (randomly chosen)
    0 0					# Length (assume 0 < length < 65536)
    (((any - 0) 0) | (any (any - 0)))
    ;
tacacs = tacacs_plus @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 107;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

snmp1_or_2c =
  0x30 any+		# (SEQUENCE)
  0x02 1 (0 | 1)	# Version: 1 (0) or 2c (1) (INTEGER)
  0x04 any # any*	# Community string (OCTET STRING)
  # any*  		# Data
  ;
snmp3 =
  0x30 any+		# (SEQUENCE)
  0x02 1 3		# Version: 3 (INTEGER)
  0x30 any # any*	# Message Global Header (SEQUENCE)
  # any*		# Data
  ;
snmp = (snmp1_or_2c | snmp3) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 98;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any* ;

openft_peer_handshake =
    0x00 0x00 0x00 0x00			# unused
    0x00 0x08				# length of handshake message
    0x00 0x01				# handshake command
    0x00 0x00				# major version (0)
    0x00 0x02				# minor version (2)
    0x00 any				# micro version
    0x00 any				# revision
    ;
openft_filetransfer = 
    "GET " [^ ]+ " HTTP/1.0\r\n"	# file transfer request
    (((any - [\r])+ "\r\n")*) :>>	# additional headers
    "Range: bytes="i			# range of byes to receive
    ;
openft = ( openft_peer_handshake | openft_filetransfer ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 65;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

sip_request =
    ("INVITE" |
     "CANCEL" |
     "MESSAGE" |
     "REGISTER" )
    " "					# Space
    "sip:"i				# Request-URI scheme (XXX - add others?)
    [^\r\n]*				# Request-URI (escaped spaces allowed)
    " "					# Space
    "SIP/2.0"i				# SIP-Version
    0xd 0xa;				# \r\n
sip = sip_request @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 93;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

rlogin_server_prompt =
    0x00
    "Password: "
    ;
rlogin = rlogin_server_prompt @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 86;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

mapi = 
    dcerpc_bind_pre_uuid
    dcerpc_uuid_mapi		# MAPI UUID
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 50;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
    ;

tcp_xmit_magic = 0x44 0x6D 0x64 0x54;
tcp_rcvd_magic = 0x74 0x4E 0x63 0x50;
ncp_xmit_header = 
    tcp_xmit_magic		# signature
    any{4}			# length
    0x00 0x00 0x00 0x01		# version
    0x00 0x00 0x00 0x00		# reply buffer size
    ;
ncp_rcvd_header = 
    tcp_rcvd_magic		# signature
    any{4}			# length
    ;
ncp_service_request = 
    ncp_xmit_header
    0x11 0x11			# service connection request
    0x00			# sequence number
    0xff			# connection number
    ;
ncp_service_reply = 
    ncp_rcvd_header
    0x33 0x33			# service connection reply
    0x00			# sequence number
    any				# connection number
    any				# task number
    0x00			# reserved
    0x00			# completion code (success)
    ;
ncp = ( ncp_service_request | ncp_service_reply ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 58;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

dhcp = 
    # BOOTP header
    (1 | 2)			# 1 or 2
    any* :>>			# 235 arbitrary bytes
    # DHCP
    (0x63 0x82 0x53 0x63) @1
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 24;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
    ;

	apps = dcerpc | irc | ssdp | mute | teamspeak | netflow | nntp | icy | msn | rtsp | edonkey | groupwise | vnc | svn | xmpp | ldap | http | rip | zephyr | cups | smb | syslog | gnutella | quake1 | rsync | postgresql | pop | mgcp | fasttrack | rtp | megaco | ntp | quake3 | gadugadu | ares | soap | ventrilo | ipp | ssh | kerberos_udp | h323 | smtp | x11 | imap | cvs | lpd | bittorrent | slp | rdp | bgp | nmdc | tds | daap | citrix | stun | tftp | rdt | corba | telnet | ftp | yahoo | tacacs | snmp | openft | sip | rlogin | mapi | ncp | dhcp ;
	main := apps;
}%%

%% write data;

static int
appid_default_execute(
	struct appid *a,
	struct appid_default *fsm,
	unsigned char		ip_protocol,
	unsigned short		src_ip_port,
	unsigned short		dst_ip_port,
	const unsigned char    *payload,
	int			payload_length)
{
	const unsigned char *p = payload;
	const unsigned char *pe = payload + payload_length;

%% access fsm->;
%% write exec;
/*
 * ragel doc section 5.4.4 states that 'write eof' is of no cost
 * if no machines use the EOF transitions.  DNS does, so
 * we include this in all
 */
%% write eof;

	if (fsm->cs == appid_default_error)
		return (-1);
	else if (fsm->cs >= appid_default_first_final)
		return (1);
	return (0);
}


%%{
	machine appid_any8;

	# Alphabet is 0 to 255
	alphtype unsigned char;

	# Ragel
        nfs_rpc2_call = 
    any{4}?		# Fragment header for TCP (section 10)
    any{4}		# XID
    0 0 0 0		# Type: Call (0)
    0 0 0 2		# Version: 2
    (0x00 0x01 0x86	# Program: NFS (100003) or Mount (100005)
     (0xa3 | 0xa5))
    # any{4}		# Version: Not assigned
    # any{4}		# Procedure: Not assigned
    # any{4}		# Auth credentials, Flavor: Assigned
    # any{0, 400}	#   Body: Depends on flavor
    # any{4}		# Auth verification, flavor: Assigned
    # any{0, 400}	#   Body: Depends on flavor
    # ...		# NFS call
    ;
nfs = nfs_rpc2_call @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 61;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any* ;

rpc2_call = 
    any{4}?		# Fragment header for TCP (section 10)
    any{4}		# XID
    0 0 0 0		# Type: Call (0)
    0 0 0 2		# Version: 2
    (((0 .. 5) any{3}) 	# Program: 0..5ffffff assigned (section 7.3)
    -(0x00 0x01 0x86 (0xa3 | 0xa5))) # Minus NFS (100003) and Mount (100005)
    any{4}		# Version: Not assigned
    any{4}		# Procedure: Not assigned
    # any{4}		# Auth credentials, Flavor: Assigned
    # any{0, 400}	#   Body: Depends on flavor
    # any{4}		# Auth verification, flavor: Assigned
    # any{0, 400}	#   Body: Depends on flavor
    # ...		# Call
    ;
rpc2_reply_accepted =
    any{4}?		# Fragment header for TCP (section 10)
    any{4}		# XID
    0 0 0 1		# Type: Reply (1)
    0 0 0 0		# Status: Accepted (0)
    # any{4}		# Auth verification, flavor: Assigned
    # any{0, 400}	#   Body: Depends on flavor
    # any{4}		# Status
    ;
rpc2_reply_denied = 
    any{4}?		# Fragment header for TCP (section 10)
    any{4}		# XID
    0 0 0 1		# Type: Reply (1)
    0 0 0 1		# Status: Denied (1)
    0 0 0 (0 .. 1)	# Reject status: RPC_MISMATCH (0), AUTH_ERROR (1)
    # ...		# Additional info: Depends on reject status
    ;
rpc2_reply = (rpc2_reply_accepted | rpc2_reply_denied) ;
rpc = (rpc2_call | rpc2_reply) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 87;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any* ;

	apps = nfs | rpc ;
	main := apps;
}%%

%% write data;

static int
appid_any8_execute(
	struct appid *a,
	struct appid_any8 *fsm,
	unsigned char		ip_protocol,
	unsigned short		src_ip_port,
	unsigned short		dst_ip_port,
	const unsigned char    *payload,
	int			payload_length)
{
	const unsigned char *p = payload;
	const unsigned char *pe = payload + payload_length;

%% access fsm->;
%% write exec;
/*
 * ragel doc section 5.4.4 states that 'write eof' is of no cost
 * if no machines use the EOF transitions.  DNS does, so
 * we include this in all
 */
%% write eof;

	if (fsm->cs == appid_any8_error)
		return (-1);
	else if (fsm->cs >= appid_any8_first_final)
		return (1);
	return (0);
}


%%{
	machine appid_any4;

	# Alphabet is 0 to 255
	alphtype unsigned char;

	# Ragel
        asn1_length = 
    (0x00..0x7f)  | # Short form
    (0x81 any{1}) | # Long form up to 4 bytes
    (0x82 any{2}) |
    (0x83 any{3}) |
    (0x84 any{4})
    ;
kerberos_msg_tag0 = 
    (		    # CHOICE
     0x6b |	    # AS-REP (11)
     0x6d |	    # TGS-REP (13)
     0x6e |	    # AP-REQ (14)
     0x6f |	    # AP-REP (15)
     0x74 |	    # KRB-SAFE (20)
     0x75 |	    # KRB-PRIV (21)
     0x76 |	    # KRB-CRED (22)
     0x7e	    # KRB-ERROR (30)
    )
    asn1_length     # CHOICE length
    0x30	    # SEQUENCE
    asn1_length     # SEQUENCE length
    0xa0 3  2 1 5   # Protocol version INTEGER 5 [0]
    0xa1 3  2 1     # Message type [1]
      (11 | 13..15 | 20..22 | 30)
    ;
kerberos_msg_tag1 = 
    (		    # CHOICE
     0x6a |	    # AS-REQ (10)
     0x6c	    # TGS-REQ (12)
    )
    asn1_length     # CHOICE length
    0x30	    # SEQUENCE
    asn1_length     # SEQUENCE length
    0xa1 3  2 1 5   # Protocol version INTEGER 5 [0]
    0xa2 3  2 1     # Message type [1]
      (10 | 12)
    ;
kerberos_ticket = 
    0x61	    # CHOICE: TICKET (1)
    asn1_length	    # CHOICE length
    0x30	    # SEQUENCE
    asn1_length     # SEQUENCE length
    0xa0 3  2 1 5   # Ticket version INTEGER 5 [0]
    0xa1 9 	    # Realm GeneralString [1]
    ;

git_commands = 
    ( "upload-pack" |
      "receive-pack" );
git_header = 
    any{4}			# length
    "git-"			# start of command
    git_commands		# rest of comand			
    ;
git = git_header @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 31;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

netbios_ns =
    any{2}		               # ID
    ((0x00 | 0x01 | (0x28 .. 0x41)) |  # R 0, Opcode, AA,TC,RD
     (0x80 | 0x81 | (0xa8 .. 0xc1)))   # R 1
    ((0x00 .. 0x07) |		       # RA 0, B 0
     (0x10 .. 0x17) |		       # RA 0, B 1
     (0x80 .. 0x87) |		       # RA 1, B 0
     (0x90 .. 0x97))		       # RA 1, B 1
    (0 (0 | 1)){4}	               # 4 count fields
    any* :> 0x00		       # Name (terminated with 0x00)
    0x00 (0x20 | 0x21)		       # Type (NB)
    0x00 0x01			       # Class (IN)
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 59;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
    ; 

kerberos_tcp = 
    ((any{4} kerberos_msg_tag0) |
     (any{4} kerberos_msg_tag1) |
     (any{4} kerberos_ticket))
    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 46;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
    ;

sametime_message_type = 
    ( 0x00 0x00 |		# handshake
      0x80 0x00 );		# handshake ack
sametime_message_options = 
    ( 0x00 0x00 |		# none
      0x40 0x00 |		# encrypted
      0x80 0x00 );		# has attributes
sametime_handshake = 
    0x00 0x00 0x00 any		# message length (<256)
    sametime_message_type	# message type
    sametime_message_options	# message options
    0x00 0x00 0x00 0x00		# channel id
    0x00 0x1e			# major protocol version
    any any			# minor protocol version
    ;
sametime = sametime_handshake @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 91;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

	apps = git | netbios_ns | kerberos_tcp | sametime ;
	main := apps;
}%%

%% write data;

static int
appid_any4_execute(
	struct appid *a,
	struct appid_any4 *fsm,
	unsigned char		ip_protocol,
	unsigned short		src_ip_port,
	unsigned short		dst_ip_port,
	const unsigned char    *payload,
	int			payload_length)
{
	const unsigned char *p = payload;
	const unsigned char *pe = payload + payload_length;

%% access fsm->;
%% write exec;
/*
 * ragel doc section 5.4.4 states that 'write eof' is of no cost
 * if no machines use the EOF transitions.  DNS does, so
 * we include this in all
 */
%% write eof;

	if (fsm->cs == appid_any4_error)
		return (-1);
	else if (fsm->cs >= appid_any4_first_final)
		return (1);
	return (0);
}


%%{
	machine appid_any16;

	# Alphabet is 0 to 255
	alphtype unsigned char;

	# Ragel
        afs_rx_header = 
  any{4}		# Connection epoch
  any{4}		# Connection ID
  any{4}		# Call number
  any{4}		# Sequence number
  any{4}		# Serial number
  (1..13)		# Type (1..13 assigned)
  ((0x00..0x0f) |	# Flags (bits 0-3,5 assigned)
   (0x20..0x2f))
  any			# Status (depends on call)
  (0..3)		# Security (0..3 assigned)
  any{2}		# Checksum
  (			# Service ID (See registry)
   (0x00 0x01) |
   (0x00 0x04) |
   (0x00 0x34) |
   (0x00 0x49) |
   (0x02 0xdb) |
   (0x02 0xdc) |
   (0x02 0xdd) |
   (0x57 0x2a) |
   (0xeb 0x81)
  )
  #any*			# Payload
  ;
afs =
  afs_rx_header
  @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 1;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
  ;

isakmp =
  any{8}		# Initiator cookie
  any{8}		# Responder cookie
  1..13			# Next Payload (1..13 assigned)
  0x10			# Major/minor version (1.0)
  1..5			# Exchange type (1..5 assigned)
  0x00..0x07		# Flags (bits 0..2 assigned)
  #any{4}		# Message ID
  #any{4}		# Length
  @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 44;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*
  ;

	apps = afs | isakmp ;
	main := apps;
}%%

%% write data;

static int
appid_any16_execute(
	struct appid *a,
	struct appid_any16 *fsm,
	unsigned char		ip_protocol,
	unsigned short		src_ip_port,
	unsigned short		dst_ip_port,
	const unsigned char    *payload,
	int			payload_length)
{
	const unsigned char *p = payload;
	const unsigned char *pe = payload + payload_length;

%% access fsm->;
%% write exec;
/*
 * ragel doc section 5.4.4 states that 'write eof' is of no cost
 * if no machines use the EOF transitions.  DNS does, so
 * we include this in all
 */
%% write eof;

	if (fsm->cs == appid_any16_error)
		return (-1);
	else if (fsm->cs >= appid_any16_first_final)
		return (1);
	return (0);
}


%%{
	machine appid_any;

	# Alphabet is 0 to 255
	alphtype unsigned char;

	# Ragel
        opennap_email_part = /[0-9A-Za-z\-\.\_]/;
opennap_email = opennap_email_part+ "@" opennap_email_part+;
opennap_login =
    any 0x00			# message length (assume < 256)
    0x02 0x00			# login message type
    graph+ " " graph+ " " digit{1,5} " " "\"" print+ "\"" " " digit{1,2}
    ;
opennap_login_ack =
    any 0x00			# message length (assume < 256)
    0x03 0x00			# login ack message type
    opennap_email
    ;
opennap_new_user_login =
    any 0x00			# message length (assume < 256)
    0x06 0x00			# new user login message type
    graph+ " " graph+ " " digit{1,5} " " "\"" print+ "\"" " " digit{1,2} " " opennap_email
    ;
opennap_file_transfer = 
    ( "GET"i | "SEND"i ) graph+ " " "\"" print+ "\"" " " digit+
    ;
opennap_file_browsing =
    ( "GETLIST"i | ( "SENDLIST "i graph+ "\n" ) )
    ;
opennap = ( opennap_login |
            opennap_login_ack |
	    opennap_new_user_login |
	    opennap_file_transfer |
	    opennap_file_browsing )
	    @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 66;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

iax_version_ie = 
    0x0b				# version ie type
    0x02				# ie length
    0x00 0x02				# protocol version 
    ;
iax_new = 
    (0x80..0xff) any			# 1 bit - full frame bit
					# 15 bits - src call number
    0x00 0x00 				# 1 bit - retransmission bit
					# 15 bits - dst call number
    0x00 0x00 any any			# timestamp (assume < 65536)
    0x00				# out sequence number
    0x00				# in sequence num
    0x06				# frametype - IAX (0x06)
    0x01				# subclass - NEW (0x01)
    iax_version_ie
    ;
iax = iax_new @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 36;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

sccp_register =
    any 0x00 0x00 0x00			# packet length (assume < 256)
    0x00 0x00 0x00 0x00			# reserved
    ( 0x01 | 0x81 ) 0x00 0x00 0x00	# type (register, registerack)
    ;
sccp = sccp_register @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 92;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

ssl_20 = 
    any any		    # Length
    (1 | 4)		    # Message type: Client or Server Hello
    ((2 0) | (3 0) | (3 1));# Version: SSL 2.0 or 3.0, TLS 1.0
tls_10 =
    22		    	    # Content type: Handshake (22)
    3 (0 | 1);	    	    # Version: {3, 1} (TLS 1.0)
ssl = (ssl_20 | tls_10) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 103;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

tns_connect =
    any any			# packet length
    0x00 0x00			# packet checksum
    0x01			# packet type connect
    0x00			# reserved byte
    0x00 0x00			# header checksum
    0x01 any			# version (256-511)
    0x01 0x2c			# version compatible (300)
    any any			# service options
    0x08 0x00			# session data unit size
    0x7f 0xff			# max trasmission data unit size
    any any			# nt protocol characteristics
    0x00 0x00			# line turnaround value
    0x00 0x01			# value of 1 in hardware
    ;
oracle = tns_connect @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 67;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

slsk_response = 
    any any 0x00 0x00			# message length (assume < 2^16)
    0x01 0x00 0x00 0x00			# login reply message type
    0x01				# login success flag
    any any 0x00 0x00			# string length (assume < 2^16)
    ;
slsk_login =
    any 0x00 0x00 0x00			# message length (assume < 256)
    0x01 0x00 0x00 0x00			# login message type
    any 0x00				# username length (assume < 256)
    ;
soulseek = ( slsk_login | slsk_response ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 100;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

oscar_proxy_ft = 
    any any				# length
    0x04 0x4a				# packet version (AIM_RV_PROXY_PACKETVER_DFLT)
    0x00 (0x02 | 0x03 | 0x04)		# cmd type (SEND | RECV | ACK))	
    0x00 0x00 0x00 0x00			# unknown (AIM_RV_PROXY_UNKNOWNA_DFLT)
    ((0x00 0x00) | (0x02 0x20))		# flags (client, server)
    ;
oscar_direct_ft =
    "OFT2"i				# Oscar File Transfer token
    any any				# OFT message length
    0x01 0x01				# OFT message type (PEER_TYPE_PROMPT)
    ;
oscar_direct_im =
    "ODC2"i				# Oscar Direct Connect token
    any any				# ODC message length
    0x00 0x05				# ODC message type (PEER_TYPE_DIRECTIM_ESTABLISHED)
    ;
oscar_new_connection =
    0x2a		# Command Start
    0x01		# Channel ID: New Connection
    any any		# Sequence number
    ((0x00 0x04 any any any any) | # First login: length 4
     (0x01 0x08 any any any any    # Second login: length 264
      0x00 0x06                    # Value ID: Auth cookie (6)
      0x01 0x00			   # Length: 256
      any{256}))
    ;
toc_new_connection = "FLAPON\r\n\r\n"i;
aim = ( oscar_proxy_ft | 
        oscar_new_connection | 
	oscar_direct_ft |
	oscar_direct_im |
        toc_new_connection ) @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 12;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

qq_login_token = 0x00 0x62;	# login token command (miranda, tencent)
qq_login = 0x00 0x22;		# login command (gaim)
qq_header = 
    0x02			# start tag on all QQ packets
    any{2}			# version number
    ;
qq_tcp_token_server =
    0x00 0x24			# static message length
    qq_header
    qq_login_token
    ;
qq_tcp_token_client =
    0x00 0x0f			# static message length
    qq_header
    qq_login_token
    ;
qq_udp_token =
    qq_header
    qq_login_token
    ;
qq_tcp_login =
    any{2}			# arbitrary message length
    qq_header
    qq_login
    ;
qq_udp_login = 
    qq_header
    qq_login
    ;
qq_connection = 
    ( qq_tcp_token_server |
      qq_tcp_token_client |
      qq_udp_token | 
      qq_udp_login | 
      qq_tcp_login )
    ;
qq = qq_connection @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 78;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

mysql_server_greeting =
    any 0 0    	    # Length (assume < 256 bytes)
    0		    # Packet number
    10		    # Protocol
    ascii+ 0;	    # Version string
mysql = mysql_server_greeting @{ 
    a->match_count ++;
    if(a->confidence < APPID_CONFIDENCE_NORMAL) {
        a->application = 57;
        a->confidence = APPID_CONFIDENCE_NORMAL;
        a->match_payload = a->payload_offset + (p - payload);
        if (APPID_CONFIDENCE_NORMAL > APPID_CONFIDENCE_NORMAL) fbreak;
    }
 } any*;

	apps = opennap | iax | sccp | ssl | oracle | soulseek | aim | qq | mysql ;
	main := apps;
}%%

%% write data;

static int
appid_any_execute(
	struct appid *a,
	struct appid_any *fsm,
	unsigned char		ip_protocol,
	unsigned short		src_ip_port,
	unsigned short		dst_ip_port,
	const unsigned char    *payload,
	int			payload_length)
{
	const unsigned char *p = payload;
	const unsigned char *pe = payload + payload_length;

%% access fsm->;
%% write exec;
/*
 * ragel doc section 5.4.4 states that 'write eof' is of no cost
 * if no machines use the EOF transitions.  DNS does, so
 * we include this in all
 */
%% write eof;

	if (fsm->cs == appid_any_error)
		return (-1);
	else if (fsm->cs >= appid_any_first_final)
		return (1);
	return (0);
}


struct appid_rv
appid_process(
	appid_t     *a,
	unsigned char  ip_protocol,
	unsigned short src_ip_port,
	unsigned short dst_ip_port,
	const void *payload,
	size_t      payload_length
    )
{
	int rv;
	struct appid_rv appid_rv;
	int state_machines_executed = 0;
	int state_machines_rejected = 0;
#if APPID_DEBUG
	int previous_match_count;
#endif
	/* Print payload */
#if APPID_DEBUG
	if (appid_debug) {
		printf("%s payload on ports %d and %d:\n",
			ip_protocol == IPPROTO_TCP ? "tcp" : "udp",
			src_ip_port, dst_ip_port);
		appid_hexdump(0, payload, payload_length);
		printf("\n");
	}
#endif

	/*
	 * Apply each machine if there's no match yet and the machine
	 * hasn't already rejected the stream.
	 */

	/* Apply machine 'dns' unless it's reached REJECT (-1) */
	if (a->appid_dns.cs >= 0) {
		state_machines_executed++;
#if APPID_DEBUG
		/* for debug, see if we have increasing match counts */
		previous_match_count = a->match_count;
#endif
		rv = appid_dns_execute(a,
		    &a->appid_dns, ip_protocol,
		    src_ip_port, dst_ip_port, (unsigned char *)payload,
		    payload_length);
		if (rv == -1) {		/* State machine rejection */
			a->appid_dns.cs = -1;
			state_machines_rejected++;
#if APPID_DEBUG
			if (appid_debug) printf("  REJECT dns\n");
#endif
		}
#if APPID_DEBUG
		else if (appid_debug) {
			if (previous_match_count != a->match_count) 
			        printf("  ACCEPT dns (app == %d == '%s')\n",
					a->application, appid_app_to_name(a->application));
			else 
				printf("CONTINUE dns\\n");
		}
#endif
	}
	/* Apply machine 'default' unless it's reached REJECT (-1) */
	if (a->appid_default.cs >= 0) {
		state_machines_executed++;
#if APPID_DEBUG
		/* for debug, see if we have increasing match counts */
		previous_match_count = a->match_count;
#endif
		rv = appid_default_execute(a,
		    &a->appid_default, ip_protocol,
		    src_ip_port, dst_ip_port, (unsigned char *)payload,
		    payload_length);
		if (rv == -1) {		/* State machine rejection */
			a->appid_default.cs = -1;
			state_machines_rejected++;
#if APPID_DEBUG
			if (appid_debug) printf("  REJECT default\n");
#endif
		}
#if APPID_DEBUG
		else if (appid_debug) {
			if (previous_match_count != a->match_count) 
			        printf("  ACCEPT default (app == %d == '%s')\n",
					a->application, appid_app_to_name(a->application));
			else 
				printf("CONTINUE default\\n");
		}
#endif
	}
	/* Apply machine 'any8' unless it's reached REJECT (-1) */
	if (a->appid_any8.cs >= 0) {
		state_machines_executed++;
#if APPID_DEBUG
		/* for debug, see if we have increasing match counts */
		previous_match_count = a->match_count;
#endif
		rv = appid_any8_execute(a,
		    &a->appid_any8, ip_protocol,
		    src_ip_port, dst_ip_port, (unsigned char *)payload,
		    payload_length);
		if (rv == -1) {		/* State machine rejection */
			a->appid_any8.cs = -1;
			state_machines_rejected++;
#if APPID_DEBUG
			if (appid_debug) printf("  REJECT any8\n");
#endif
		}
#if APPID_DEBUG
		else if (appid_debug) {
			if (previous_match_count != a->match_count) 
			        printf("  ACCEPT any8 (app == %d == '%s')\n",
					a->application, appid_app_to_name(a->application));
			else 
				printf("CONTINUE any8\\n");
		}
#endif
	}
	/* Apply machine 'any4' unless it's reached REJECT (-1) */
	if (a->appid_any4.cs >= 0) {
		state_machines_executed++;
#if APPID_DEBUG
		/* for debug, see if we have increasing match counts */
		previous_match_count = a->match_count;
#endif
		rv = appid_any4_execute(a,
		    &a->appid_any4, ip_protocol,
		    src_ip_port, dst_ip_port, (unsigned char *)payload,
		    payload_length);
		if (rv == -1) {		/* State machine rejection */
			a->appid_any4.cs = -1;
			state_machines_rejected++;
#if APPID_DEBUG
			if (appid_debug) printf("  REJECT any4\n");
#endif
		}
#if APPID_DEBUG
		else if (appid_debug) {
			if (previous_match_count != a->match_count) 
			        printf("  ACCEPT any4 (app == %d == '%s')\n",
					a->application, appid_app_to_name(a->application));
			else 
				printf("CONTINUE any4\\n");
		}
#endif
	}
	/* Apply machine 'any16' unless it's reached REJECT (-1) */
	if (a->appid_any16.cs >= 0) {
		state_machines_executed++;
#if APPID_DEBUG
		/* for debug, see if we have increasing match counts */
		previous_match_count = a->match_count;
#endif
		rv = appid_any16_execute(a,
		    &a->appid_any16, ip_protocol,
		    src_ip_port, dst_ip_port, (unsigned char *)payload,
		    payload_length);
		if (rv == -1) {		/* State machine rejection */
			a->appid_any16.cs = -1;
			state_machines_rejected++;
#if APPID_DEBUG
			if (appid_debug) printf("  REJECT any16\n");
#endif
		}
#if APPID_DEBUG
		else if (appid_debug) {
			if (previous_match_count != a->match_count) 
			        printf("  ACCEPT any16 (app == %d == '%s')\n",
					a->application, appid_app_to_name(a->application));
			else 
				printf("CONTINUE any16\\n");
		}
#endif
	}
	/* Apply machine 'any' unless it's reached REJECT (-1) */
	if (a->appid_any.cs >= 0) {
		state_machines_executed++;
#if APPID_DEBUG
		/* for debug, see if we have increasing match counts */
		previous_match_count = a->match_count;
#endif
		rv = appid_any_execute(a,
		    &a->appid_any, ip_protocol,
		    src_ip_port, dst_ip_port, (unsigned char *)payload,
		    payload_length);
		if (rv == -1) {		/* State machine rejection */
			a->appid_any.cs = -1;
			state_machines_rejected++;
#if APPID_DEBUG
			if (appid_debug) printf("  REJECT any\n");
#endif
		}
#if APPID_DEBUG
		else if (appid_debug) {
			if (previous_match_count != a->match_count) 
			        printf("  ACCEPT any (app == %d == '%s')\n",
					a->application, appid_app_to_name(a->application));
			else 
				printf("CONTINUE any\\n");
		}
#endif
	}

	a->all_machines_rejected = state_machines_executed == state_machines_rejected;

#if APPID_DEBUG
	if (appid_debug) {
		printf("%d machines didn't reject payload\n",
			state_machines_executed - state_machines_rejected);
		printf("a->application=%d (%s)\n",
			a->application, appid_app_to_name(a->application));
		printf("a->confidence=%d\n", a->confidence);
		printf("ip_protocol=%d\n", ip_protocol);
		printf("a->match_count=%d\n", a->match_count);
		printf("a->payload_offset=%zd\n", a->payload_offset);
		printf("a->all_machines_rejected=%d\n", a->all_machines_rejected);
	}
#endif
	a->payload_offset += payload_length;
	appid_rv.application = a->application;
	appid_rv.confidence = a->confidence;
	if (a->all_machines_rejected)
		appid_rv.application = APPID_UNKNOWN;
	return appid_rv;
}
			    
appid_t *
appid_open(void)
{
	struct appid *a;

	if ((a = calloc(1, sizeof(*a))) == NULL)
		return NULL;
	
	a->application = APPID_CONTINUE;
	a->confidence = APPID_CONFIDENCE_UNKNOWN;
	a->all_machines_rejected = 0;
	a->payload_offset = 0;
	
	memset(&a->appid_dns, 0,
	    sizeof(a->appid_dns));
	a->appid_dns.cs = appid_dns_start;
	memset(&a->appid_default, 0,
	    sizeof(a->appid_default));
	a->appid_default.cs = appid_default_start;
	memset(&a->appid_any8, 0,
	    sizeof(a->appid_any8));
	a->appid_any8.cs = appid_any8_start;
	memset(&a->appid_any4, 0,
	    sizeof(a->appid_any4));
	a->appid_any4.cs = appid_any4_start;
	memset(&a->appid_any16, 0,
	    sizeof(a->appid_any16));
	a->appid_any16.cs = appid_any16_start;
	memset(&a->appid_any, 0,
	    sizeof(a->appid_any));
	a->appid_any.cs = appid_any_start;
       return a;
}

void
appid_close(appid_t **a)
{
	free(*a);
	*a = NULL;
}
