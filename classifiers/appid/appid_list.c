/*
 * Application ID library
 *  
 * Copyright (c) 2005-2007 Arbor Networks, Inc.
 *
 * $Arbor: appid_list.c,v 1.1 2007/02/07 15:57:53 pha Exp $
 */ 

#include <stdio.h>

#include "appid.h"

#define DEBUG_APPID_LIST 1

/*
 * appid_metadata provides various bits of metadata about an
 * application.
 *
 *   short_name    -> 'internal' name - lower case, no spaces, etc
 *   full_name     -> external name - mixed case, spaces, < 64 chars
 *   description   -> one or more line description
 *   port_list     -> string listing port/protocols, undefined format
 */

struct appid_metadata {
	const char *short_name;
	const char *full_name;
	const char *description;
	const char *port_list;
};

extern struct appid_metadata appid_metadata[];

struct appid_metadata appid_metadata[MAX_APPID] = {
    [APPID_AFS] = {
        "afs",
        "AFS",
        "",
        "['udp/7000', 'udp/7001', 'udp/7002', 'udp/7003', 'udp/7004', 'udp/7005', 'udp/7007', 'udp/7008', 'udp/7009', 'udp/7021', 'udp/7025', 'udp/7100']",
    },
    [APPID_AIM] = {
        "aim",
        "AIM",
        "",
        "['tcp/5190']",
    },
    [APPID_ARES] = {
        "ares",
        "Ares",
        "",
        "['tcp/59049']",
    },
    [APPID_BGP] = {
        "bgp",
        "BGP",
        "",
        "['tcp/179']",
    },
    [APPID_BITTORRENT] = {
        "bittorrent",
        "BitTorrent",
        "",
        "['tcp/*']",
    },
    [APPID_CITRIX] = {
        "citrix",
        "Citrix",
        "",
        "['tcp/1494', 'udp/1494', 'tcp/1604', 'udp/1604']",
    },
    [APPID_CORBA] = {
        "corba",
        "CORBA",
        "",
        "['tcp/683']",
    },
    [APPID_CUPS] = {
        "cups",
        "CUPS",
        "",
        "['udp/631']",
    },
    [APPID_CVS] = {
        "cvs",
        "CVS",
        "",
        "['tcp/2401']",
    },
    [APPID_DAAP] = {
        "daap",
        "DAAP",
        "",
        "['tcp/3689']",
    },
    [APPID_DCERPC] = {
        "dcerpc",
        "DCERPC",
        "",
        "['udp/*', 'tcp/*']",
    },
    [APPID_DHCP] = {
        "dhcp",
        "DHCP",
        "",
        "['udp/67', 'tcp/67', 'udp/68', 'tcp/68']",
    },
    [APPID_DNS] = {
        "dns",
        "DNS",
        "",
        "['udp/53', 'udp/5353']",
    },
    [APPID_EDONKEY] = {
        "edonkey",
        "Edonkey",
        "",
        "['udp/*', 'tcp/*']",
    },
    [APPID_FASTTRACK] = {
        "fasttrack",
        "FastTrack",
        "",
        "['udp/*', 'tcp/*']",
    },
    [APPID_FTP] = {
        "ftp",
        "FTP",
        "",
        "['tcp/21']",
    },
    [APPID_GADUGADU] = {
        "gadugadu",
        "GaduGadu",
        "",
        "['tcp/8074']",
    },
    [APPID_GIT] = {
        "git",
        "Git",
        "",
        "['tcp/9418']",
    },
    [APPID_GNUTELLA] = {
        "gnutella",
        "Gnutella",
        "",
        "['udp/*', 'tcp/*']",
    },
    [APPID_GROUPWISE] = {
        "groupwise",
        "Groupwise",
        "",
        "['tcp/8300']",
    },
    [APPID_H323] = {
        "h323",
        "H323",
        "",
        "['tcp/1720']",
    },
    [APPID_HTTP] = {
        "http",
        "HTTP",
        "",
        "['tcp/80', 'tcp/8080']",
    },
    [APPID_IAX] = {
        "iax",
        "IAX",
        "",
        "['udp/4569']",
    },
    [APPID_ICY] = {
        "icy",
        "ICY",
        "",
        "['tcp/*']",
    },
    [APPID_IMAP] = {
        "imap",
        "IMAP",
        "",
        "['tcp/143']",
    },
    [APPID_IPP] = {
        "ipp",
        "IPP",
        "",
        "['tcp/631']",
    },
    [APPID_IRC] = {
        "irc",
        "IRC",
        "",
        "['tcp/6667']",
    },
    [APPID_ISAKMP] = {
        "isakmp",
        "ISAKMP",
        "",
        "['udp/500']",
    },
    [APPID_KERBEROS_UDP] = {
        "kerberos_udp",
        "Kerberos",
        "",
        "['udp/88', 'udp/4444']",
    },
    [APPID_KERBEROS_TCP] = {
        "kerberos_tcp",
        "Kerberos",
        "",
        "['tcp/88', 'tcp/4444']",
    },
    [APPID_LDAP] = {
        "ldap",
        "LDAP",
        "",
        "['tcp/389', 'udp/389']",
    },
    [APPID_LPD] = {
        "lpd",
        "LPD",
        "",
        "['tcp/515']",
    },
    [APPID_MAPI] = {
        "mapi",
        "MAPI",
        "",
        "['udp/*', 'tcp/*']",
    },
    [APPID_MEGACO] = {
        "megaco",
        "Megaco",
        "",
        "['tcp/2944', 'udp/2944', 'tcp/2945', 'udp/2945']",
    },
    [APPID_MGCP] = {
        "mgcp",
        "MGCP",
        "",
        "['udp/2727', 'udp/2427']",
    },
    [APPID_MSN] = {
        "msn",
        "MSN",
        "",
        "['tcp/1863']",
    },
    [APPID_MUTE] = {
        "mute",
        "MUTE",
        "",
        "['tcp/4900']",
    },
    [APPID_MYSQL] = {
        "mysql",
        "MySQL",
        "",
        "['tcp/3306']",
    },
    [APPID_NCP] = {
        "ncp",
        "NCP",
        "",
        "['tcp/524']",
    },
    [APPID_NETBIOS_NS] = {
        "netbios_ns",
        "NetBIOS_NS",
        "",
        "['udp/137']",
    },
    [APPID_NETFLOW] = {
        "netflow",
        "NetFlow",
        "",
        "['udp/5000']",
    },
    [APPID_NFS] = {
        "nfs",
        "NFS",
        "",
        "['udp/*', 'tcp/*']",
    },
    [APPID_NMDC] = {
        "nmdc",
        "NMDC",
        "",
        "['tcp/411', 'udp/411']",
    },
    [APPID_NNTP] = {
        "nntp",
        "NNTP",
        "",
        "['tcp/119']",
    },
    [APPID_NTP] = {
        "ntp",
        "NTP",
        "",
        "['udp/123']",
    },
    [APPID_OPENFT] = {
        "openft",
        "OpenFT",
        "",
        "['tcp/1216']",
    },
    [APPID_OPENNAP] = {
        "opennap",
        "OpenNAP",
        "",
        "['tcp/3456', 'tcp/6699', 'tcp/7777', 'tcp/8888']",
    },
    [APPID_ORACLE] = {
        "oracle",
        "Oracle",
        "",
        "['tcp/1521', 'udp/1521']",
    },
    [APPID_POP] = {
        "pop",
        "POP",
        "",
        "['tcp/110']",
    },
    [APPID_POSTGRESQL] = {
        "postgresql",
        "PostgreSQL",
        "",
        "['tcp/5432']",
    },
    [APPID_QQ] = {
        "qq",
        "QQ",
        "",
        "['tcp/8000', 'udp/8000']",
    },
    [APPID_QUAKE1] = {
        "quake1",
        "Quake1",
        "",
        "['udp/26000']",
    },
    [APPID_QUAKE3] = {
        "quake3",
        "Quake3",
        "",
        "['udp/27960', 'udp/27910']",
    },
    [APPID_RADIUS] = {
        "radius",
        "RADIUS",
        "",
        "['udp/1812']",
    },
    [APPID_RDP] = {
        "rdp",
        "RDP",
        "",
        "['tcp/3389']",
    },
    [APPID_RDT] = {
        "rdt",
        "RDT",
        "",
        "['udp/6970', 'tcp/6970']",
    },
    [APPID_RIP] = {
        "rip",
        "RIP",
        "",
        "['udp/520']",
    },
    [APPID_RLOGIN] = {
        "rlogin",
        "Rlogin",
        "",
        "['tcp/513']",
    },
    [APPID_RPC] = {
        "rpc",
        "RPC",
        "",
        "['udp/*', 'tcp/*']",
    },
    [APPID_RSYNC] = {
        "rsync",
        "Rsync",
        "",
        "['tcp/873']",
    },
    [APPID_RTP] = {
        "rtp",
        "RTP",
        "",
        "['udp/5004']",
    },
    [APPID_RTSP] = {
        "rtsp",
        "RTSP",
        "",
        "['tcp/554', 'udp/554']",
    },
    [APPID_SAMETIME] = {
        "sametime",
        "Sametime",
        "",
        "['tcp/1533']",
    },
    [APPID_SCCP] = {
        "sccp",
        "SCCP",
        "",
        "['tcp/2000']",
    },
    [APPID_SIP] = {
        "sip",
        "SIP",
        "",
        "['tcp/5060', 'udp/5060']",
    },
    [APPID_SLP] = {
        "slp",
        "SLP",
        "",
        "['tcp/427', 'udp/427']",
    },
    [APPID_SMB] = {
        "smb",
        "SMB",
        "",
        "['udp/138', 'tcp/139', 'tcp/445']",
    },
    [APPID_SMTP] = {
        "smtp",
        "SMTP",
        "",
        "['tcp/25']",
    },
    [APPID_SNMP] = {
        "snmp",
        "SNMP",
        "",
        "['udp/161', 'udp/162']",
    },
    [APPID_SOAP] = {
        "soap",
        "SOAP",
        "",
        "['tcp/*']",
    },
    [APPID_SOULSEEK] = {
        "soulseek",
        "Soulseek",
        "",
        "['tcp/2240']",
    },
    [APPID_SSDP] = {
        "ssdp",
        "SSDP",
        "",
        "['udp/1900']",
    },
    [APPID_SSH] = {
        "ssh",
        "SSH",
        "",
        "['tcp/22']",
    },
    [APPID_SSL] = {
        "ssl",
        "SSL",
        "",
        "['tcp/443', 'tcp/993', 'tcp/995']",
    },
    [APPID_STUN] = {
        "stun",
        "STUN",
        "",
        "['udp/3478']",
    },
    [APPID_SVN] = {
        "svn",
        "SVN",
        "",
        "['tcp/3690']",
    },
    [APPID_SYSLOG] = {
        "syslog",
        "Syslog",
        "",
        "['udp/514']",
    },
    [APPID_TACACS] = {
        "tacacs",
        "TACACS",
        "",
        "['tcp/49']",
    },
    [APPID_TDS] = {
        "tds",
        "TDS",
        "",
        "['tcp/1433']",
    },
    [APPID_TEAMSPEAK] = {
        "teamspeak",
        "TeamSpeak",
        "",
        "['udp/8766', 'tcp/8765']",
    },
    [APPID_TELNET] = {
        "telnet",
        "Telnet",
        "",
        "['tcp/23']",
    },
    [APPID_TFTP] = {
        "tftp",
        "TFTP",
        "",
        "['udp/69']",
    },
    [APPID_VENTRILO] = {
        "ventrilo",
        "Ventrilo",
        "",
        "['tcp/3784', 'udp/3784']",
    },
    [APPID_VNC] = {
        "vnc",
        "VNC",
        "",
        "['tcp/5901']",
    },
    [APPID_X11] = {
        "x11",
        "X11",
        "",
        "['tcp/6000']",
    },
    [APPID_XMPP] = {
        "xmpp",
        "XMPP",
        "",
        "['tcp/5222', 'tcp/5269']",
    },
    [APPID_YAHOO] = {
        "yahoo",
        "Yahoo",
        "",
        "['tcp/5050']",
    },
    [APPID_ZEPHYR] = {
        "zephyr",
        "Zephyr",
        "",
        "['udp/2102', 'udp/2103', 'udp/2104']",
    },
    [APPID_GOPHER] = {
        "gopher",
        "Gopher",
        "",
        "['tcp/70']",
    },
};

const char *
appid_app_to_name(int appid)
{
#if DEBUG_APPID_LIST
    static char buf[256];
#endif
    switch(appid) {
        case APPID_AFS: return "AFS";
        case APPID_AIM: return "AIM";
        case APPID_ARES: return "Ares";
        case APPID_BGP: return "BGP";
        case APPID_BITTORRENT: return "BitTorrent";
        case APPID_CITRIX: return "Citrix";
        case APPID_CORBA: return "CORBA";
        case APPID_CUPS: return "CUPS";
        case APPID_CVS: return "CVS";
        case APPID_DAAP: return "DAAP";
        case APPID_DCERPC: return "DCERPC";
        case APPID_DHCP: return "DHCP";
        case APPID_DNS: return "DNS";
        case APPID_EDONKEY: return "Edonkey";
        case APPID_FASTTRACK: return "FastTrack";
        case APPID_FTP: return "FTP";
        case APPID_GADUGADU: return "GaduGadu";
        case APPID_GIT: return "Git";
        case APPID_GNUTELLA: return "Gnutella";
        case APPID_GROUPWISE: return "Groupwise";
        case APPID_H323: return "H323";
        case APPID_HTTP: return "HTTP";
        case APPID_IAX: return "IAX";
        case APPID_ICY: return "ICY";
        case APPID_IMAP: return "IMAP";
        case APPID_IPP: return "IPP";
        case APPID_IRC: return "IRC";
        case APPID_ISAKMP: return "ISAKMP";
        case APPID_KERBEROS_UDP: return "Kerberos";
        case APPID_KERBEROS_TCP: return "Kerberos";
        case APPID_LDAP: return "LDAP";
        case APPID_LPD: return "LPD";
        case APPID_MAPI: return "MAPI";
        case APPID_MEGACO: return "Megaco";
        case APPID_MGCP: return "MGCP";
        case APPID_MSN: return "MSN";
        case APPID_MUTE: return "MUTE";
        case APPID_MYSQL: return "MySQL";
        case APPID_NCP: return "NCP";
        case APPID_NETBIOS_NS: return "NetBIOS_NS";
        case APPID_NETFLOW: return "NetFlow";
        case APPID_NFS: return "NFS";
        case APPID_NMDC: return "NMDC";
        case APPID_NNTP: return "NNTP";
        case APPID_NTP: return "NTP";
        case APPID_OPENFT: return "OpenFT";
        case APPID_OPENNAP: return "OpenNAP";
        case APPID_ORACLE: return "Oracle";
        case APPID_POP: return "POP";
        case APPID_POSTGRESQL: return "PostgreSQL";
        case APPID_QQ: return "QQ";
        case APPID_QUAKE1: return "Quake1";
        case APPID_QUAKE3: return "Quake3";
        case APPID_RADIUS: return "RADIUS";
        case APPID_RDP: return "RDP";
        case APPID_RDT: return "RDT";
        case APPID_RIP: return "RIP";
        case APPID_RLOGIN: return "Rlogin";
        case APPID_RPC: return "RPC";
        case APPID_RSYNC: return "Rsync";
        case APPID_RTP: return "RTP";
        case APPID_RTSP: return "RTSP";
        case APPID_SAMETIME: return "Sametime";
        case APPID_SCCP: return "SCCP";
        case APPID_SIP: return "SIP";
        case APPID_SLP: return "SLP";
        case APPID_SMB: return "SMB";
        case APPID_SMTP: return "SMTP";
        case APPID_SNMP: return "SNMP";
        case APPID_SOAP: return "SOAP";
        case APPID_SOULSEEK: return "Soulseek";
        case APPID_SSDP: return "SSDP";
        case APPID_SSH: return "SSH";
        case APPID_SSL: return "SSL";
        case APPID_STUN: return "STUN";
        case APPID_SVN: return "SVN";
        case APPID_SYSLOG: return "Syslog";
        case APPID_TACACS: return "TACACS";
        case APPID_TDS: return "TDS";
        case APPID_TEAMSPEAK: return "TeamSpeak";
        case APPID_TELNET: return "Telnet";
        case APPID_TFTP: return "TFTP";
        case APPID_VENTRILO: return "Ventrilo";
        case APPID_VNC: return "VNC";
        case APPID_X11: return "X11";
        case APPID_XMPP: return "XMPP";
        case APPID_YAHOO: return "Yahoo";
        case APPID_ZEPHYR: return "Zephyr";
        case APPID_GOPHER: return "Gopher";
        default:
#if DEBUG_APPID_LIST
            snprintf(buf, sizeof(buf), "UNKNOWN ID %d", appid);
            return buf;
#else
            return "UNKNOWN";
#endif
    }
    return "UNKNOWN";   /* NOTREACHED */
}       

int
appid_uses_port(int app, int protocol, int port)
{
    if (protocol == 6) {  /* IPPROTO_TCP */
        switch (app) {
            case APPID_OPENFT: {
                if (port == 1216) return 1;
            }
            case APPID_TELNET: {
                if (port == 23) return 1;
            }
            case APPID_MUTE: {
                if (port == 4900) return 1;
            }
            case APPID_XMPP: {
                if (port == 5222 || port == 5269) return 1;
            }
            case APPID_MYSQL: {
                if (port == 3306) return 1;
            }
            case APPID_SMTP: {
                if (port == 25) return 1;
            }
            case APPID_GOPHER: {
                if (port == 70) return 1;
            }
            case APPID_H323: {
                if (port == 1720) return 1;
            }
            case APPID_ORACLE: {
                if (port == 1521) return 1;
            }
            case APPID_NCP: {
                if (port == 524) return 1;
            }
            case APPID_IPP: {
                if (port == 631) return 1;
            }
            case APPID_SCCP: {
                if (port == 2000) return 1;
            }
            case APPID_CITRIX: {
                if (port == 1494 || port == 1604) return 1;
            }
            case APPID_VNC: {
                if (port == 5901) return 1;
            }
            case APPID_VENTRILO: {
                if (port == 3784) return 1;
            }
            case APPID_FTP: {
                if (port == 21) return 1;
            }
            case APPID_CORBA: {
                if (port == 683) return 1;
            }
            case APPID_GIT: {
                if (port == 9418) return 1;
            }
            case APPID_KERBEROS_TCP: {
                if (port == 88 || port == 4444) return 1;
            }
            case APPID_DAAP: {
                if (port == 3689) return 1;
            }
            case APPID_MSN: {
                if (port == 1863) return 1;
            }
            case APPID_LDAP: {
                if (port == 389) return 1;
            }
            case APPID_DHCP: {
                if (port == 67 || port == 68) return 1;
            }
            case APPID_IRC: {
                if (port == 6667) return 1;
            }
            case APPID_NNTP: {
                if (port == 119) return 1;
            }
            case APPID_SMB: {
                if (port == 139 || port == 445) return 1;
            }
            case APPID_ARES: {
                if (port == 59049) return 1;
            }
            case APPID_SVN: {
                if (port == 3690) return 1;
            }
            case APPID_RTSP: {
                if (port == 554) return 1;
            }
            case APPID_HTTP: {
                if (port == 80 || port == 8080) return 1;
            }
            case APPID_SAMETIME: {
                if (port == 1533) return 1;
            }
            case APPID_TEAMSPEAK: {
                if (port == 8765) return 1;
            }
            case APPID_GROUPWISE: {
                if (port == 8300) return 1;
            }
            case APPID_SSL: {
                if (port == 443 || port == 993 || port == 995) return 1;
            }
            case APPID_RSYNC: {
                if (port == 873) return 1;
            }
            case APPID_YAHOO: {
                if (port == 5050) return 1;
            }
            case APPID_AIM: {
                if (port == 5190) return 1;
            }
            case APPID_SIP: {
                if (port == 5060) return 1;
            }
            case APPID_NMDC: {
                if (port == 411) return 1;
            }
            case APPID_OPENNAP: {
                if (port == 3456 || port == 6699 || port == 7777 || port == 8888) return 1;
            }
            case APPID_POP: {
                if (port == 110) return 1;
            }
            case APPID_TDS: {
                if (port == 1433) return 1;
            }
            case APPID_IMAP: {
                if (port == 143) return 1;
            }
            case APPID_SSH: {
                if (port == 22) return 1;
            }
            case APPID_X11: {
                if (port == 6000) return 1;
            }
            case APPID_QQ: {
                if (port == 8000) return 1;
            }
            case APPID_RDT: {
                if (port == 6970) return 1;
            }
            case APPID_LPD: {
                if (port == 515) return 1;
            }
            case APPID_POSTGRESQL: {
                if (port == 5432) return 1;
            }
            case APPID_RDP: {
                if (port == 3389) return 1;
            }
            case APPID_MEGACO: {
                if (port == 2944 || port == 2945) return 1;
            }
            case APPID_RLOGIN: {
                if (port == 513) return 1;
            }
            case APPID_SLP: {
                if (port == 427) return 1;
            }
            case APPID_CVS: {
                if (port == 2401) return 1;
            }
            case APPID_BGP: {
                if (port == 179) return 1;
            }
            case APPID_TACACS: {
                if (port == 49) return 1;
            }
            case APPID_GADUGADU: {
                if (port == 8074) return 1;
            }
            case APPID_SOULSEEK: {
                if (port == 2240) return 1;
            }
        }
    } else if (protocol == 17) { /* IPPROTO_UDP */
        switch (app) {
            case APPID_ORACLE: {
                if (port == 1521) return 1;
            }
            case APPID_SYSLOG: {
                if (port == 514) return 1;
            }
            case APPID_RADIUS: {
                if (port == 1812) return 1;
            }
            case APPID_RTP: {
                if (port == 5004) return 1;
            }
            case APPID_CITRIX: {
                if (port == 1494 || port == 1604) return 1;
            }
            case APPID_CUPS: {
                if (port == 631) return 1;
            }
            case APPID_VENTRILO: {
                if (port == 3784) return 1;
            }
            case APPID_SNMP: {
                if (port == 161 || port == 162) return 1;
            }
            case APPID_ISAKMP: {
                if (port == 500) return 1;
            }
            case APPID_IAX: {
                if (port == 4569) return 1;
            }
            case APPID_DNS: {
                if (port == 53 || port == 5353) return 1;
            }
            case APPID_LDAP: {
                if (port == 389) return 1;
            }
            case APPID_NETBIOS_NS: {
                if (port == 137) return 1;
            }
            case APPID_DHCP: {
                if (port == 67 || port == 68) return 1;
            }
            case APPID_SMB: {
                if (port == 138) return 1;
            }
            case APPID_RTSP: {
                if (port == 554) return 1;
            }
            case APPID_TEAMSPEAK: {
                if (port == 8766) return 1;
            }
            case APPID_NTP: {
                if (port == 123) return 1;
            }
            case APPID_QUAKE3: {
                if (port == 27960 || port == 27910) return 1;
            }
            case APPID_QUAKE1: {
                if (port == 26000) return 1;
            }
            case APPID_SIP: {
                if (port == 5060) return 1;
            }
            case APPID_NMDC: {
                if (port == 411) return 1;
            }
            case APPID_RIP: {
                if (port == 520) return 1;
            }
            case APPID_NETFLOW: {
                if (port == 5000) return 1;
            }
            case APPID_QQ: {
                if (port == 8000) return 1;
            }
            case APPID_RDT: {
                if (port == 6970) return 1;
            }
            case APPID_MEGACO: {
                if (port == 2944 || port == 2945) return 1;
            }
            case APPID_STUN: {
                if (port == 3478) return 1;
            }
            case APPID_SLP: {
                if (port == 427) return 1;
            }
            case APPID_TFTP: {
                if (port == 69) return 1;
            }
            case APPID_ZEPHYR: {
                if (port == 2102 || port == 2103 || port == 2104) return 1;
            }
            case APPID_SSDP: {
                if (port == 1900) return 1;
            }
            case APPID_AFS: {
                if (port == 7000 || port == 7001 || port == 7002 || port == 7003 || port == 7004 || port == 7005 || port == 7007 || port == 7008 || port == 7009 || port == 7021 || port == 7025 || port == 7100) return 1;
            }
            case APPID_MGCP: {
                if (port == 2727 || port == 2427) return 1;
            }
            case APPID_KERBEROS_UDP: {
                if (port == 88 || port == 4444) return 1;
            }
        }
    }
    return 0;
}

int
appid_port_to_app(int protocol, int port)
{
    if (protocol == 6) { /* IPPROTO_TCP */
        switch (port) {
            case 1216: return APPID_OPENFT;
            case 23: return APPID_TELNET;
            case 4900: return APPID_MUTE;
            case 5222: return APPID_XMPP;
            case 5269: return APPID_XMPP;
            case 3306: return APPID_MYSQL;
            case 25: return APPID_SMTP;
            case 70: return APPID_GOPHER;
            case 1720: return APPID_H323;
            case 1521: return APPID_ORACLE;
            case 524: return APPID_NCP;
            case 631: return APPID_IPP;
            case 2000: return APPID_SCCP;
            case 1494: return APPID_CITRIX;
            case 1604: return APPID_CITRIX;
            case 5901: return APPID_VNC;
            case 3784: return APPID_VENTRILO;
            case 21: return APPID_FTP;
            case 683: return APPID_CORBA;
            case 9418: return APPID_GIT;
            case 88: return APPID_KERBEROS_TCP;
            case 4444: return APPID_KERBEROS_TCP;
            case 3689: return APPID_DAAP;
            case 1863: return APPID_MSN;
            case 389: return APPID_LDAP;
            case 67: return APPID_DHCP;
            case 68: return APPID_DHCP;
            case 6667: return APPID_IRC;
            case 119: return APPID_NNTP;
            case 139: return APPID_SMB;
            case 445: return APPID_SMB;
            case 59049: return APPID_ARES;
            case 3690: return APPID_SVN;
            case 554: return APPID_RTSP;
            case 80: return APPID_HTTP;
            case 8080: return APPID_HTTP;
            case 1533: return APPID_SAMETIME;
            case 8765: return APPID_TEAMSPEAK;
            case 8300: return APPID_GROUPWISE;
            case 443: return APPID_SSL;
            case 993: return APPID_SSL;
            case 995: return APPID_SSL;
            case 873: return APPID_RSYNC;
            case 5050: return APPID_YAHOO;
            case 5190: return APPID_AIM;
            case 5060: return APPID_SIP;
            case 411: return APPID_NMDC;
            case 3456: return APPID_OPENNAP;
            case 6699: return APPID_OPENNAP;
            case 7777: return APPID_OPENNAP;
            case 8888: return APPID_OPENNAP;
            case 110: return APPID_POP;
            case 1433: return APPID_TDS;
            case 143: return APPID_IMAP;
            case 22: return APPID_SSH;
            case 6000: return APPID_X11;
            case 8000: return APPID_QQ;
            case 6970: return APPID_RDT;
            case 515: return APPID_LPD;
            case 5432: return APPID_POSTGRESQL;
            case 3389: return APPID_RDP;
            case 2944: return APPID_MEGACO;
            case 2945: return APPID_MEGACO;
            case 513: return APPID_RLOGIN;
            case 427: return APPID_SLP;
            case 2401: return APPID_CVS;
            case 179: return APPID_BGP;
            case 49: return APPID_TACACS;
            case 8074: return APPID_GADUGADU;
            case 2240: return APPID_SOULSEEK;
        }
    } else if (protocol == 17) { /* IPPROTO_UDP */
        switch (port) {
            case 1521: return APPID_ORACLE;
            case 514: return APPID_SYSLOG;
            case 1812: return APPID_RADIUS;
            case 5004: return APPID_RTP;
            case 1494: return APPID_CITRIX;
            case 1604: return APPID_CITRIX;
            case 631: return APPID_CUPS;
            case 3784: return APPID_VENTRILO;
            case 161: return APPID_SNMP;
            case 162: return APPID_SNMP;
            case 500: return APPID_ISAKMP;
            case 4569: return APPID_IAX;
            case 53: return APPID_DNS;
            case 5353: return APPID_DNS;
            case 389: return APPID_LDAP;
            case 137: return APPID_NETBIOS_NS;
            case 67: return APPID_DHCP;
            case 68: return APPID_DHCP;
            case 138: return APPID_SMB;
            case 554: return APPID_RTSP;
            case 8766: return APPID_TEAMSPEAK;
            case 123: return APPID_NTP;
            case 27960: return APPID_QUAKE3;
            case 27910: return APPID_QUAKE3;
            case 26000: return APPID_QUAKE1;
            case 5060: return APPID_SIP;
            case 411: return APPID_NMDC;
            case 520: return APPID_RIP;
            case 5000: return APPID_NETFLOW;
            case 8000: return APPID_QQ;
            case 6970: return APPID_RDT;
            case 2944: return APPID_MEGACO;
            case 2945: return APPID_MEGACO;
            case 3478: return APPID_STUN;
            case 427: return APPID_SLP;
            case 69: return APPID_TFTP;
            case 2102: return APPID_ZEPHYR;
            case 2103: return APPID_ZEPHYR;
            case 2104: return APPID_ZEPHYR;
            case 1900: return APPID_SSDP;
            case 7000: return APPID_AFS;
            case 7001: return APPID_AFS;
            case 7002: return APPID_AFS;
            case 7003: return APPID_AFS;
            case 7004: return APPID_AFS;
            case 7005: return APPID_AFS;
            case 7007: return APPID_AFS;
            case 7008: return APPID_AFS;
            case 7009: return APPID_AFS;
            case 7021: return APPID_AFS;
            case 7025: return APPID_AFS;
            case 7100: return APPID_AFS;
            case 2727: return APPID_MGCP;
            case 2427: return APPID_MGCP;
            case 88: return APPID_KERBEROS_UDP;
            case 4444: return APPID_KERBEROS_UDP;
        }
    }
    return APPID_UNKNOWN;
}
