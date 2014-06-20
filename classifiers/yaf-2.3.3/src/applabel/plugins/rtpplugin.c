/**
 * @file aolplugin.c
 *
 *
 * This tries to recognize the Real Time Transport Protocol (RTP)
 * and associated RTP Control Protocol (RTCP) session.
 * Based on RFC 3550.
 *
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

#define RTP_PORT_NUMBER 5004
#define RTCP_PORT_NUMBER 5005

typedef struct ycRtpScanMessageHeader_st {
    uint16_t      version:2;
    uint16_t      padding:1;
    uint16_t      extension:1;
    uint16_t      csrc:4;
    uint16_t      marker:1;
    uint16_t      paytype:7;

    uint16_t      sequence;
    uint32_t      timestamp;
    uint32_t      ssrc;

} ycRtpScanMessageHeader_t;


typedef struct ycRtcpScanMessageHeader_st {
    uint8_t      version:2;
    uint8_t      padding:1;
    uint8_t      count:5;

    uint8_t      packet_type;
    uint16_t     length;
    uint32_t     ssrc;
} ycRtcpScanMessageHeader_t;



/* Local Prototypes */

static
void
ycRtpScanRebuildHeader (
    uint8_t * payload,
    ycRtpScanMessageHeader_t * header);


static
void
ycRtcpScanRebuildHeader(
    uint8_t *payload,
    ycRtcpScanMessageHeader_t * header);


/**
 * rtpplugin_LTX_ycRtpScanScan
 *
 * the scanner for recognizing RTP/RTCP packets
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
 * @return rtp_port_number
 *         otherwise 0
 */

uint16_t
rtpplugin_LTX_ycRtpScanScan(
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{

    ycRtpScanMessageHeader_t header;
    ycRtcpScanMessageHeader_t rtcp_header;
    uint16_t offset = 0;

    if (payloadSize < 12) {
        return 0;
    }

    if (flow->key.proto != 17) {
        /* this only does RTP over UDP */
        return 0;
    }

    ycRtpScanRebuildHeader(payload, &header);

    if (header.version != 2) {
        /* version 2 is standard */
        return 0;
    }

    if (header.paytype > 34) {

        if ((header.paytype > 71) && (header.paytype < 77)) {
            goto rtcp;
        }

        if (header.paytype < 71) {
            return 0;
        }

        if ((header.paytype > 76) && (header.paytype < 96)) {
            return 0;
        }

    }

    offset += 12;

    if (header.csrc > 0) {
        int csrc_count = (header.csrc > 15) ? 15 : header.csrc;
        int csrc_length = csrc_count * 4;

        if ((payloadSize - offset) < csrc_length) {
            return 0;
        }

        offset += csrc_length;
    }

    if (header.extension) {
        uint16_t extension_length;

        if (offset + 4 > payloadSize) {
            return 0;
        }

        offset += 2;

        extension_length = ntohs(*((uint16_t *)(payload + offset)));

        offset += 2;

        if ((offset + extension_length) > payloadSize) {
            return 0;
        }

        offset += extension_length;
    }

    if (header.sequence == 0) {
        return 0;
    }
    if (header.timestamp == 0) {
        return 0;
    }
    if (header.ssrc == 0) {
        return 0;
    }

    return RTP_PORT_NUMBER;


  rtcp:

    offset = 0;

    ycRtcpScanRebuildHeader(payload, &rtcp_header);

    if (rtcp_header.count > 0) {
        return 0;
    }

    /* must be a report pkt first */
    if (rtcp_header.packet_type != 201) {
        return 0;
    }
    /* report packets are 1 byte */
    if (rtcp_header.length > 1) {
        return 0;
    }

    offset += 8;

    if (offset + 8 > payloadSize) {
        return 0;
    }

    /* get second RTCP */

    ycRtcpScanRebuildHeader((payload + offset), &rtcp_header);

    offset += 8;

    if (rtcp_header.version != 2) {
        return 0;
    }

    if (rtcp_header.packet_type < 191) {
        return 0;
    }

    if (rtcp_header.packet_type > 211) {
        return 0;
    }

    if ((offset + rtcp_header.length) > payloadSize) {
        return 0;
    }

    if (rtcp_header.ssrc == 0) {
        return 0;
    }

    if (rtcp_header.count) {
        uint8_t sdes_type;
        uint8_t sdes_len;

        /* get type */

        sdes_type = *(payload + offset);

        if (sdes_type > 9) {
            return 0;
        }

        offset++;

        sdes_len = *(payload + offset);

        if (sdes_len + offset > payloadSize) {
            return 0;
        }

        /* DPI? */
    }

    return RTCP_PORT_NUMBER;

}


/**
 * ycRtpScanRebuildHeader
 *
 * This function handles the endianess of the received message and
 * deals with machine alignment issues by not mapping a network
 * octect stream directly into the DNS structure
 *
 * @param payload a network stream capture
 * @param header a pointer to a client allocated dns message
 *        header structure
 *
 *
 */
static
void
ycRtpScanRebuildHeader (
    uint8_t * payload,
    ycRtpScanMessageHeader_t * header)
{
    uint16_t            bitmasks = ntohs(*((uint16_t *)payload));

    header->version = (bitmasks & 0xC000) >> 14;
    header->padding = bitmasks & 0x2000 ? 1 : 0;
    header->extension = bitmasks & 0x1000 ? 1 : 0;
    header->csrc = (bitmasks & 0x0F00) >> 8;
    header->marker = bitmasks & 0x0080 ? 1 : 0;
    header->paytype = bitmasks & 0x007F;

    header->sequence = ntohs(*((uint16_t *)(payload + 2)));

    header->timestamp = ntohl(*((uint32_t *)(payload + 4)));

    header->ssrc = ntohl(*((uint32_t *)(payload + 8)));

    /*    g_debug("header->version %d", header->version);
    g_debug("header->padding %d", header->padding);
    g_debug("header->extension %d", header->extension);
    g_debug("header->csrc %d", header->csrc);
    g_debug("header->marker %d", header->marker);
    g_debug("header->paytype %d", header->paytype);
    g_debug("header->sequence %d", header->sequence);
    g_debug("header->timestamp %d", header->timestamp);
    g_debug("header->ssrc %d", header->ssrc);*/
}


static
void
ycRtcpScanRebuildHeader(
    uint8_t *payload,
    ycRtcpScanMessageHeader_t * header)
{

    uint8_t bitmasks = *payload;

    header->version = (bitmasks & 0xC0) >> 6;
    header->padding = bitmasks & 0x20 ? 1 : 0;
    header->count = bitmasks & 0x1F;

    header->packet_type = *(payload + 1);

    header->length = ntohs(*((uint16_t *)(payload + 2)));

    header->ssrc = ntohl(*((uint32_t *)(payload + 4)));

    /*
    g_debug("header->version %d", header->version);
    g_debug("header->padding %d", header->padding);
    g_debug("header->count %d", header->count);

    g_debug("header_pkt type %d", header->packet_type);
    g_debug("header->length is %d", header->length);
    */
}
