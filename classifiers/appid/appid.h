/*
 * Application ID library
 *
 * Copyright (c) 2005-2007 Arbor Networks, Inc.
 *
 * $Arbor: appid.h,v 1.6 2006/12/12 20:34:56 dhelder Exp $
 */

#ifndef APPID_H
#define APPID_H

/* Match confidence. */
#define APPID_CONFIDENCE_UNKNOWN	0
#define APPID_CONFIDENCE_PORTLOOKUP	1
#define APPID_CONFIDENCE_LOW		2
#define APPID_CONFIDENCE_NORMAL		3
#define APPID_CONFIDENCE_HIGH		4

/* Application IDs. */
#define APPID_CONTINUE       -1		/* Unknown, continue calling */
#define APPID_UNKNOWN	     0		/* Unknown, stop calling */
#define APPID_AFS            1  	/* afs */
#define APPID_AIM            12 	/* aim */
#define APPID_ARES           13 	/* ares */
#define APPID_BGP            14 	/* bgp */
#define APPID_BITTORRENT     15 	/* bittorrent */
#define APPID_CITRIX         16 	/* citrix */
#define APPID_CORBA          19 	/* corba */
#define APPID_CUPS           20 	/* cups */
#define APPID_CVS            21 	/* cvs */
#define APPID_DAAP           22 	/* daap */
#define APPID_DCERPC         23 	/* dcerpc */
#define APPID_DHCP           24 	/* dhcp */
#define APPID_DNS            25 	/* dns */
#define APPID_EDONKEY        26 	/* edonkey */
#define APPID_FASTTRACK      28 	/* fasttrack */
#define APPID_FTP            29 	/* ftp */
#define APPID_GADUGADU       30 	/* gadugadu */
#define APPID_GIT            31 	/* git */
#define APPID_GNUTELLA       32 	/* gnutella */
#define APPID_GROUPWISE      33 	/* groupwise */
#define APPID_H323           34 	/* h323 */
#define APPID_HTTP           35 	/* http */
#define APPID_IAX            36 	/* iax */
#define APPID_ICY            38 	/* icy */
#define APPID_IMAP           40 	/* imap */
#define APPID_IPP            41 	/* ipp */
#define APPID_IRC            43 	/* irc */
#define APPID_ISAKMP         44 	/* isakmp */
#define APPID_KERBEROS_UDP   45 	/* kerberos_udp */
#define APPID_KERBEROS_TCP   46 	/* kerberos_tcp */
#define APPID_LDAP           47 	/* ldap */
#define APPID_LPD            49 	/* lpd */
#define APPID_MAPI           50 	/* mapi */
#define APPID_MEGACO         52 	/* megaco */
#define APPID_MGCP           53 	/* mgcp */
#define APPID_MSN            55 	/* msn */
#define APPID_MUTE           56 	/* mute */
#define APPID_MYSQL          57 	/* mysql */
#define APPID_NCP            58 	/* ncp */
#define APPID_NETBIOS_NS     59 	/* netbios_ns */
#define APPID_NETFLOW        60 	/* netflow */
#define APPID_NFS            61 	/* nfs */
#define APPID_NMDC           62 	/* nmdc */
#define APPID_NNTP           63 	/* nntp */
#define APPID_NTP            64 	/* ntp */
#define APPID_OPENFT         65 	/* openft */
#define APPID_OPENNAP        66 	/* opennap */
#define APPID_ORACLE         67 	/* oracle */
#define APPID_POP            75 	/* pop */
#define APPID_POSTGRESQL     76 	/* postgresql */
#define APPID_QQ             78 	/* qq */
#define APPID_QUAKE1         79 	/* quake1 */
#define APPID_QUAKE3         80 	/* quake3 */
#define APPID_RADIUS         81 	/* radius */
#define APPID_RDP            82 	/* rdp */
#define APPID_RDT            83 	/* rdt */
#define APPID_RIP            85 	/* rip */
#define APPID_RLOGIN         86 	/* rlogin */
#define APPID_RPC            87 	/* rpc */
#define APPID_RSYNC          88 	/* rsync */
#define APPID_RTP            89 	/* rtp */
#define APPID_RTSP           90 	/* rtsp */
#define APPID_SAMETIME       91 	/* sametime */
#define APPID_SCCP           92 	/* sccp */
#define APPID_SIP            93 	/* sip */
#define APPID_SLP            95 	/* slp */
#define APPID_SMB            96 	/* smb */
#define APPID_SMTP           97 	/* smtp */
#define APPID_SNMP           98 	/* snmp */
#define APPID_SOAP           99 	/* soap */
#define APPID_SOULSEEK       100	/* soulseek */
#define APPID_SSDP           101	/* ssdp */
#define APPID_SSH            102	/* ssh */
#define APPID_SSL            103	/* ssl */
#define APPID_STUN           104	/* stun */
#define APPID_SVN            105	/* svn */
#define APPID_SYSLOG         106	/* syslog */
#define APPID_TACACS         107	/* tacacs */
#define APPID_TDS            108	/* tds */
#define APPID_TEAMSPEAK      109	/* teamspeak */
#define APPID_TELNET         110	/* telnet */
#define APPID_TFTP           111	/* tftp */
#define APPID_VENTRILO       112	/* ventrilo */
#define APPID_VNC            113	/* vnc */
#define APPID_X11            114	/* x11 */
#define APPID_XMPP           117	/* xmpp */
#define APPID_YAHOO          118	/* yahoo */
#define APPID_ZEPHYR         119	/* zephyr */
#define APPID_GOPHER         120	/* gopher */
#define MAX_APPID            121

struct appid_rv {
	int     application;
	int     confidence;
};

typedef struct appid appid_t;

/* Return a new appid handle, or NULL on failure. */
appid_t *appid_open(void);

/*
 * Process data.  
 * Returns APPID_CONTINUE, APPID_UNKNOWN, or a positive appid.
 *
 * ip_protocol -> IPPROTO_TCP or IPPROTO_UDP
 *
 * src_ip_port -> host order port number (direction A)
 * dst_ip_port -> host order port number (direction B)
 *
 * payload -> byte payload data
 * len -> payload length
 *
 */
struct appid_rv appid_process(appid_t *a,
    unsigned char proto, unsigned short sport, unsigned short dport,
    const void *payload, size_t len);

/* Close an appid handle. */
void appid_close(appid_t **a);

/* Check if appid uses a given port. */
int appid_uses_port(int app, int proto, int port);

/* Return the appid for a given port. */
int appid_port_to_app(int proto, int port);

/* Convert appid to name. */
const char *appid_app_to_name(int appid);


/* Debugging */
extern int appid_debug;
extern void appid_dump_match_conflict(void);

/* simple hex dump */
void appid_hexdump(int n, const void *buffer, int length);

#endif /* APPID_H */
