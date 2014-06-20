/**
 ** @file getFlowKeyHash.c
 *
 * This program determines the filename for a given flow
 * when using the --pcap-per-flow option with YAF.
 * Given IPs, ports, protocol, vlan, and start time -
 * this program will give the filename of the pcap
 * for the particular flow.  This uses YAF's flow key hash
 * function to calculate the hash, and given the time
 * date can calculate which directory the file resides in.
 *
 * the pcap-per-flow option writes a pcap file for each
 * flow it processes, in the file directory given to --pcap.
 * Based on the last 3 digits of the flow's start time
 * milliseconds, the flow key hash, and the flow's start
 * time, you can find the pcap file which contains the entire
 * flow.
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2013 Carnegie Mellon University.
 ** All Rights Reserved.
 **
 ** ------------------------------------------------------------------------
 ** Author: Emily Sarneso <ecoff@cert.org>
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the YAF system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU Public License (GPL) Rights pursuant to Version 2, June 1991
 ** Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
 **
 ** NO WARRANTY
 **
 ** ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
 ** PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
 ** PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
 ** "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
 ** KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
 ** LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
 ** MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
 ** OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
 ** SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
 ** TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
 ** WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
 ** LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
 ** CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
 ** CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
 ** DELIVERABLES UNDER THIS LICENSE.
 **
 ** Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
 ** Mellon University, its trustees, officers, employees, and agents from
 ** all claims or demands made against them (and any related losses,
 ** expenses, or attorney's fees) arising out of, or relating to Licensee's
 ** and/or its sub licensees' negligent use or willful misuse of or
 ** negligent conduct or willful misconduct regarding the Software,
 ** facilities, or other rights or assistance granted by Carnegie Mellon
 ** University under this License, including, but not limited to, any
 ** claims of product liability, personal injury, death, damage to
 ** property, or violation of any laws or regulations.
 **
 ** Carnegie Mellon University Software Engineering Institute authored
 ** documents are sponsored by the U.S. Department of Defense under
 ** Contract FA8721-05-C-0003. Carnegie Mellon University retains
 ** copyrights in all material produced under this contract. The U.S.
 ** Government retains a non-exclusive, royalty-free license to publish or
 ** reproduce these documents, or allow others to do so, for U.S.
 ** Government purposes only pursuant to the copyright license under the
 ** contract clause at 252.227.7013.
 **
 ** @OPENSOURCE_HEADER_END@
 ** ------------------------------------------------------------------------
 *
 */


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <libgen.h>
#include <glib.h>
#include <string.h>
#include <airframe/airutil.h>

static char * sip = NULL;
static char * dip = NULL;
static char * sip6 = NULL;
static char * dip6 = NULL;
static char * dport = NULL;
static char * sport = NULL;
static char * protocol = NULL;
static char * vlan = NULL;
static char * date = NULL;
static char * user_time = NULL;
static GOptionEntry md_core_option[] = {
    {"sip4", 's', 0, G_OPTION_ARG_STRING, &sip, "Source IPv4 in form 127.0.0.1. Req.",
     NULL},
    {"dip4", 'd', 0, G_OPTION_ARG_STRING, &dip, "Destination IPv4 in form 127.0.0.1 Req.",
     NULL},
    {"sip6", 0, 0, G_OPTION_ARG_STRING, &sip6,"Source IPv6 in form 2001:48af::1:1",
     NULL},
    {"dip6", 0, 0, G_OPTION_ARG_STRING, &dip6, "Destination IPv6 Address",
     NULL},
    {"sport", 'o', 0, G_OPTION_ARG_STRING, &sport, "Source Port Req.", NULL},
    {"dport", 'r', 0, G_OPTION_ARG_STRING, &dport, "Destination Port Req.", NULL},
    {"protocol", 'p', 0, G_OPTION_ARG_STRING, &protocol, "Protocol Req.",
     NULL},
    {"vlan", 'v', 0, G_OPTION_ARG_STRING, &vlan, "vlan [0]", NULL},
    {"date", 'y', 0, G_OPTION_ARG_STRING, &date, "DATE form: 2009-01-23 [0]", NULL},
    {"time", 't', 0, G_OPTION_ARG_STRING, &user_time, "TIME form: 22:54:23.343 [0]",
     NULL},
    { NULL }
};



uint32_t convertIP4Address(
    char *ipaddr_buf)
{

    uint32_t ip;

    if (inet_aton(ipaddr_buf, (struct in_addr *)&ip) == 0) {
        fprintf(stderr, "Invalid IP Address\n");
        exit(-1);
    }

    return g_ntohl(ip);
}

void convertIP6Address(
    char      *ipaddr_buf,
    uint8_t   *ip6)
{
    if (inet_pton(AF_INET6, ipaddr_buf, ip6) <= 0) {
        fprintf(stderr, "Invalid IPv6 Address\n");
        exit(-1);
    }
}


/**
 * main
 *
 */
int
main (int argc, char *argv[]) {

    GOptionContext *ctx = NULL;
    GError *err = NULL;
    uint32_t source_ip = 0;
    uint32_t destination_ip = 0;
    uint8_t sp6[16];
    uint8_t dp6[16];
    uint16_t sp = 0;
    uint16_t dp = 0;
    uint8_t proto = 0;
    uint16_t vlan2 = 0;
    uint32_t year, month, day, hour, sec, min, ms;
    uint32_t key_hash = 0;
    time_t epoch_ms;
    gchar **split;
    uint32_t *v6p;

    ctx = g_option_context_new(" - getFlowKeyHash Options");

    g_option_context_add_main_entries(ctx, md_core_option, NULL);

    g_option_context_set_help_enabled(ctx, TRUE);

    if (!g_option_context_parse(ctx, &argc, &argv, &err)) {
        fprintf(stderr, "option parsing failed: %s\n", err->message);
        exit(-1);
    }

    memset(sp6, 0, 16);
    memset(dp6, 0, 16);

    if ((!sip && !sip6) || (!dip && !dip6)) {
        fprintf(stderr, "Error: Need --sip[4|6] or --dip[4|6]\n");
        fprintf(stderr, "Use --help for usage.\n");
        exit(-1);
    }

    if (sip) {
        source_ip = convertIP4Address(sip);
    }
    if (dip) {
        destination_ip = convertIP4Address(dip);
    }
    if (sip6) {
        convertIP6Address(sip6, sp6);
    }
    if (dip6) {
        convertIP6Address(dip6, dp6);
    }
    if (sport) {
        sp = atoi(sport);
    }
    if (dport) {
        dp = atoi(dport);
    }
    if (protocol) {
        proto = atoi(protocol);
    }
    if (vlan) {
        vlan2 = atoi(vlan);
    }

    if (sip6 && dip6) {
        v6p = (uint32_t *)sp6;
        key_hash = (sp << 16) ^ dp ^
                   (proto << 12) ^ (6 << 4) ^
                   (vlan2 << 20) ^ *v6p;
        v6p++;
        key_hash ^= *v6p;
        v6p++;
        key_hash ^= *v6p;
        v6p++;
        key_hash ^= *v6p;
        v6p = (uint32_t *)dp6;
        key_hash ^= *v6p;
        v6p++;
        key_hash ^= *v6p;
        v6p++;
        key_hash ^= *v6p;
        v6p++;
        key_hash ^= *v6p;
    } else if (sip && dip) {
        key_hash = (sp << 16) ^ dp ^ (proto << 12) ^ (4 << 4) ^
                   (vlan2 << 20) ^ source_ip ^ destination_ip;
    }

    if (date && user_time) {
        split = g_strsplit(date, "-", -1);
        if (split[0]) {
            year = atoi(split[0]);
        } else {
            fprintf(stderr, "Invalid Date. Correct Format 2012-03-07\n");
            exit(-1);
        }
        if (split[1]) {
            month = atoi(split[1]);
        } else {
            fprintf(stderr, "Invalid Date. Correct Format 2012-03-07\n");
            exit(-1);
        }
        if (split[2]) {
            day = atoi(split[2]);
        } else {
            fprintf(stderr, "Invalid Date. Correct Format 2012-03-07\n");
            exit(-1);
        }

        split = g_strsplit(user_time, ":", -1);
        if (split[0]) {
            hour = atoi(split[0]);
        } else {
            fprintf(stderr, "Invalid Time. Correct Format 07:21:33.345\n");
            exit(-1);
        }

        if (split[1]) {
            min = atoi(split[1]);
        } else {
            fprintf(stderr, "Invalid Time. Correct Format 07:21:33.345\n");
            exit(-1);
        }

        if (split[2]) {
            sec = atoi(split[2]);
        } else {
            fprintf(stderr, "Invalid Time. Correct Format 07:21:33.345\n");
            exit(-1);
        }

        split = g_strsplit(user_time, ".", -1);
        if (split[1]) {
            ms = atoi(split[1]);
        } else {
            ms = 0;
            printf("Missing milliseconds.  Milliseconds determines Directory\n");
        }

        epoch_ms = air_time_gm(year, month, day, hour, min, sec);

        printf("\nKEY HASH: %u\n", key_hash);
        printf("\nFILE PATH: %03d/%u-%d%d%d%d%d%d_0.pcap\n", ms, key_hash, year, month,
               day, hour, min, sec);
        printf("\nMS since EPOCH: %llu%d\n", (long long unsigned int)epoch_ms, ms);

        g_strfreev(split);

    } else {

        printf("\nKEY HASH: %u\n", key_hash);
        printf("\nFILE PATH: sss/%u_YYYYMMDDHHMMSS_0\n", key_hash);
    }

    g_option_context_free(ctx);

    return 0;
}
