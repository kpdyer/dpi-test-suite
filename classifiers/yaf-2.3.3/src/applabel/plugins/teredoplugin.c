/**
 *@internal
 *
 *@file teredoplugin.c
 *
 * @brief this is a protocol classifier for the Teredo Tunneling Protocol
 *
 * Teredo is a tunneling protocol designed to grant IPv6 connectivity to
 * nodes that are located behind IPv6-unaware NAT devices.  It is a way to
 * encapsulate IPv6 pkts within IPv4 UDP datagrams.
 *
 * @sa rfc 4380  href="http://tools.ietf.org/html/rfc4380"
 *
 *
 * @author $Author: ecoff_svn $
 * @date $Date: 2010-01-20 15:54:44 -0500 (Wed, 20 Jan 2010) $
 * @version $Revision: 15242 $
 *
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2007-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Dan Ruef <druef@cert.org>
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


#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>

#include <arpa/inet.h>

/**
 * IPv6 header structure.
 */
typedef struct yfHdrIPv6_st {
    /** Version, traffic class, and flow ID. Use YF_VCF6_ macros to access. */
    uint32_t         ip6_vcf;

    /**
     * Payload length. Does NOT include IPv6 header (40 bytes), but does
     * include subsequent extension headers, upper layer headers, and payload.
     */
    uint16_t        ip6_plen;
    /** Next header identifier. Use YF_PROTO_ macros. */
    uint8_t         ip6_nxt;
    /** Hop limit */
    uint8_t         ip6_hlim;
    /** Source IPv6 address */
    uint8_t         ip6_src[16];
    /** Destination IPv6 address */
    uint8_t         ip6_dst[16];
} yfHdrIPv6_t;

#define AUTH_HEADER_LEN 13
typedef struct yfIPv6AuthIndicator_st {
    /* indicator type, set to 1 for auth */
    uint16_t        ipv6_indicatorType;
    /* length of the client ID string that follows auth data length */
    uint8_t         ipv6_clientIdLen;
    /* length of the authentication data that follow client id string */
    uint8_t         ipv6_authenticationDataLen;
    /* char * clientId.  There is a char array of variable length next */
    /* uint8_t *authenticationData.  There is a variable array of auth data */
    uint64_t        nonce;
    uint8_t         confirmation;
} yfIPv6AuthIndicator_t;

typedef struct yfIPv6OriginIndicator_st {
    /* indicator type, set to 0 for origin */
    uint16_t        ipv6_indicatorType;
    uint16_t        ipv6_obscuredPortNum;
    uint32_t        ipv6_obscuredOriginAddress;
} yfIPv6OriginIndicator_t;

static uint16_t lookForIPv6HdrAndTeredoAddrs(yfHdrIPv6_t *ipv6Hdr);

#define TEREDO_PORT_NUMBER 3544

/**
 * teredoplugin_LTX_ycTeredoScan
 *
 * returns TEREDO_PORT_NUMBER if the passed in payload matches
 * a teredo IPv6 tunneling protocol packet
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * return 0 if no match
 */

uint16_t
teredoplugin_LTX_ycTeredoScanScan (
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{
    yfHdrIPv6_t                *ipv6Hdr;
    yfIPv6AuthIndicator_t      *authHdr;
    yfIPv6OriginIndicator_t    *originHdr;
    int                         retval;
    int                         authHdrLength = 0;
    uint16_t                    indicator;

    if (payloadSize < sizeof(yfHdrIPv6_t)){
            return 0;
    }

    ipv6Hdr = (yfHdrIPv6_t*) payload;

    retval = lookForIPv6HdrAndTeredoAddrs(ipv6Hdr);
    if (retval == TEREDO_PORT_NUMBER) {
        return TEREDO_PORT_NUMBER;
    }

    authHdr = (yfIPv6AuthIndicator_t *) payload;

    indicator = ntohs(authHdr->ipv6_indicatorType);
    if (authHdr->ipv6_indicatorType == 1) {
        authHdrLength = AUTH_HEADER_LEN +
                        authHdr->ipv6_clientIdLen     +
                        authHdr->ipv6_authenticationDataLen;

        if (payloadSize < (authHdrLength + sizeof(yfHdrIPv6_t))) {
            return 0;
        }

        originHdr = (yfIPv6OriginIndicator_t*)(payload + authHdrLength);
        indicator = ntohs(originHdr->ipv6_indicatorType);
        if (indicator == 0) {
            if (payloadSize < (authHdrLength +
                               sizeof(yfHdrIPv6_t) +
                               sizeof(yfIPv6OriginIndicator_t)))
            {
                return 0;
            }
            ipv6Hdr = (yfHdrIPv6_t*)(originHdr + 1);

        } else {
            ipv6Hdr = (yfHdrIPv6_t*)originHdr;
        }
    } else {
        originHdr = (yfIPv6OriginIndicator_t*)payload;
        indicator = ntohs(originHdr->ipv6_indicatorType);
        if (indicator != 0) {
            return 0;
        }

        if (payloadSize < sizeof(yfIPv6OriginIndicator_t) +
                          sizeof(yfHdrIPv6_t))
        {
            return 0;
        }

        ipv6Hdr = (yfHdrIPv6_t*)(originHdr + 1);
    }

    return lookForIPv6HdrAndTeredoAddrs(ipv6Hdr);
}

static uint16_t lookForIPv6HdrAndTeredoAddrs(
    yfHdrIPv6_t *ipv6Hdr)
{
    uint32_t    teredoPrefix = htonl(0x20010000);
    uint32_t    vcf = 0;

    vcf = ntohl(ipv6Hdr->ip6_vcf);

    if (((vcf & 0xF0000000) >> 28) != 6) {
        return 0;
    }

    /* try teredo data...prefix...then try icmp for router solicitation */
    if (memcmp(&teredoPrefix, ipv6Hdr->ip6_src, 4) != 0) {
        if (memcmp(&teredoPrefix, ipv6Hdr->ip6_dst, 4) != 0) {
            return 0;
        }
    }

    return TEREDO_PORT_NUMBER;
}
