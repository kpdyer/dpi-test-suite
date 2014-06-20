/**
 * @file dhcpplugin.c
 *
 *
 * This tries to recognize the DHCP protocol
 * rfc 2131
 *
 * The Dynamic Host Configuration Protocol (DHCP) provides a framework
 * for passing configuration information to hosts on a TCPIP network.
 * It is based on the Bootstrap Protocol (BOOTP) adding the add'l
 * capability of automatic allocation of reusable network addresses
 * and add'l config options.
 *
 * @author $Author: ecoff_svn $
 * @date $Date: 2010-07-26 09:28:45 -0400 (Mon, 26 Jul 2010) $
 * @Version $Revision: 16060 $
 *
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2007-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso <ecoff@cert.org>
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

#define DHCP_PORT_NUMBER 67
#define MAGICCOOKIE 0x63825363

/**
 * dhcpplugin_LTX_ycDhcpScanScan
 *
 * the scanner for recognizing DHCP packets
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * @return dhcp port number
 *         otherwise 0
 */

uint16_t
dhcpplugin_LTX_ycDhcpScanScan(
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{
    uint8_t         op, htype;
    uint16_t        flags, offsetptr = 0;
    uint32_t        magic_cookie;
    int             loop;


    if (payloadSize < 44) {
        return 0;
    }
    if (flow->key.proto != YF_PROTO_UDP) {
        return 0;
    }

    /* MESSAGE TYPE */
    op = payload[0];
    if (op != 2 && op != 1) {
        return 0;   /* BOOTREPLY = 2, BOOTREQUEST = 1 */
    }
    offsetptr++;

    /* Hardware type */
    htype = *(payload + offsetptr);
    if (htype != 1) {
        return 0;
    }

    /* hardware len is after type */

    offsetptr+=2;

    /* hops should be 0 */
    if (*(payload + offsetptr) != 0) {
        return 0;
    }

    /* transaction ID next & then seconds elapsed */
    offsetptr += 7;

    flags = ntohs(*(uint16_t *)(payload + offsetptr));
    if (flags != 0x8000 && flags != 0) {
        return 0;  /* only 1 (Broadcast flag) bit can be set) */
    }

    /* client addr is after flags - can be different based on type of message */
    offsetptr += 6;

    if (op == 1) {
        /* yiaddr, siaddr, and giaddr should be 0 */
        for (loop = 0; loop < 12; loop++) {
            if (*(payload + offsetptr + loop) != 0) {
                return 0;
            }
        }
    }
    /* 12 for above yiaddr, siaddr, and giaddr, 16 for chaddr */
    offsetptr += 28;
    /* 64 for sname, 128 for file, 4 for magic cookie */
    if (offsetptr + 196 <= payloadSize) {
        offsetptr += 192;
    } else {
        /* should be good enough - but magic cookie will secure the decision */
        return DHCP_PORT_NUMBER;
    }

    magic_cookie = ntohl(*(uint32_t *)(payload + offsetptr));
    if (magic_cookie != MAGICCOOKIE) {
        return 0;
    }

    offsetptr += 4;
    if (offsetptr >= payloadSize) {
        /* just enough */
        return DHCP_PORT_NUMBER;
    }

    /* OPTIONS SECTION! */

    return DHCP_PORT_NUMBER;
}
