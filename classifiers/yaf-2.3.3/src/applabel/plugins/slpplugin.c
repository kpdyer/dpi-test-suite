/**
 *@internal
 *
 *@file slpplugin.c
 *
 *@brief this is a protocol classifier for the service location protocol (SLP)
 *
 * SLP is a protocol to find well known protocol/services on a local area
 * network.  It can scale from small scale networks to large lan networks.
 * For small scale networks, it uses multicasting in order to ask all
 * machines for a service.  In larger networks it uses Directory Agents
 * in order to centralize management of service information and increase
 * scaling by decreasing network load.
 *
 * @sa rfc 2608  href="http://www.ietf.org/rfc/rfc2608.txt"
 *
 *
 * @author $Author: ecoff_svn $
 * @date $Date: 2013-01-29 15:29:45 -0500 (Tue, 29 Jan 2013) $
 * @version $Revision: 18678 $
 *
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2007-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Chris Inacio <inacio@cert.org>
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

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#include <arpa/inet.h>


typedef struct srcLocProtoHeader_v1_st {
    uint8_t             version;
    uint8_t             function;
    uint16_t            length;

    uint8_t             overflow:1;
    uint8_t             monolingual:1;
    uint8_t             urlAuth:1;
    uint8_t             attribAuth:1;
    uint8_t             srvcAck:1;
    uint8_t             reserved:3;

    uint8_t             dialect;
    uint16_t            langCode;
    uint16_t            charEncoding;
    uint16_t            xid;
} srcLocProtoHeader_v1_t;

struct srcLocProtoHeader_v1_st __attribute__ ((packed));

/** this structure does not match (bit-for-bit anyway)  the
    on the wire protocol.  Machines without native 24-bit
    int types (darn near everything except some DSPs & older
    video chips maybe) will not be able to pack it correctly
    to match the wire */
typedef struct srcLocProtoHeader_v2_st {
    uint8_t             version;
    uint8_t             function;

    /* this is really a 24-bit value */
    uint32_t            length;

    uint8_t             overflow:1;
    uint8_t             fresh:1;
    uint8_t             reqMcast:1;
    uint16_t            reserved:13;

    /* this is really a 24-bit value */
    uint32_t            nextExtensionOffset;

    uint16_t            xid;

    uint16_t            langTagLength;
    uint8_t             langCode;       /* there is at least 1 char here, and
                                         * up to 8 */
} srcLocProtoHeader_v2_t;

/* this is the size of the V2 header up to and including the language
   tag length in uint8_t/octects/bytes */
#define SLP_V2_HEADER_SIZE 14

typedef enum slpFunction_et {
    SrvReq = 1,
    SrvRply = 2,
    SrvReg = 3,
    SrvDereg = 4,
    SrvAck = 5,
    AttrRqst = 6,
    AttrRply = 7,
    DAAdvert = 8,
    SrvTypeRqst = 9,
    SrvTypeReply = 10,
    SAAdvert = 11
} slpFunction_t;


#define SLP_PORT_NUMBER 427


/*
 * File local functions
 *
 */
static unsigned int ycPopulateSLPV2Header (
    uint8_t * payload,
    unsigned int payloadSize,
    srcLocProtoHeader_v2_t * header);




/**
 * slpplugin_LTX_ycSlpScanScan
 *
 * returns SLP_PORT_NUMBER if the passed in payload matches a service location
 * protocol packet
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
 * @return 0 if not a match, if it is SLP, returns the version of the protocol
 */
uint16_t
slpplugin_LTX_ycSlpScanScan (
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{

    uint8_t             version;
    srcLocProtoHeader_v1_t *slpHeader;
    unsigned int        loop;

#if YAF_ENABLE_HOOKS
    gboolean slpStringFound = FALSE;
    uint16_t slplength[5];
    uint16_t slpoffset[5];
    for (loop = 0; loop < 5; loop++){
            slplength[loop] = 0;
            slpoffset[loop] = 0;
    }
#endif

    if (0 == payloadSize) {
        return 0;
    }


    /* map the payload into an SLP structure */
    slpHeader = (srcLocProtoHeader_v1_t *) payload;
    version = slpHeader->version;

    /* Sufficient payload for at least a header? */
    if (((payloadSize < sizeof (srcLocProtoHeader_v1_t)) && (1 == version)) ||
        ((payloadSize < sizeof (srcLocProtoHeader_v2_t)) && (2 == version)))
    {
        return 0;
    }


    if (1 == version) {
        /* check the reserved fields first, they are required to be zero */
        if ((0 != slpHeader->reserved) || (0 != slpHeader->dialect)) {
            return 0;
        }

        /* check for a valid function code */
        if ((slpHeader->function < SrvReq)
            || (slpHeader->function > SrvTypeReply))
        {
            return 0;
        }

#if YAF_ENABLE_HOOKS
    /* version */
        /*yfHookScanPayload(flow, payload, sizeof(uint8_t), NULL, 0, 90,
          SLP_PORT_NUMBER);*/
    /* msg type */
        /*yfHookScanPayload(flow, payload, sizeof(uint8_t), NULL, 1, 91,
          SLP_PORT_NUMBER);*/

    /*Nothing valuable for now*/
/*    offset = 13;
    for (loop = 0; loop < 2; loop++){
        yfHookScanPayload(flow, payload, *(payload+offset),
                  NULL, (offset + sizeof(uint16_t)), 92+loop,
                  SLP_PORT_NUMBER);
        offset += *(payload+offset) + sizeof(uint16_t);
        }*/
#endif

        /* seems likely that this might be a service location protocol, let's
         * run with that as the answer */
        return 1;

    } else if (2 == version) {
        srcLocProtoHeader_v2_t slpHeader2;
        uint16_t            offset;


        if (0 == ycPopulateSLPV2Header (payload, payloadSize, &slpHeader2)) {
            return 0;
        }

        /* make sure the reserved field is set to zero, as required */
        if (0 != slpHeader2.reserved) {
            return 0;
        }

        /* check for a valid function code */
        if ((slpHeader2.function < SrvReq) && (slpHeader2.function > SAAdvert))
        {
            return 0;
        }

        /* check the length of the language tag field */
        if (slpHeader2.langTagLength < 1 || slpHeader2.langTagLength > 8) {
            /* this is an invalid language length */
            return 0;
        }

        /* substract the size of the single langCode, but then we need to add
         * the length of the language string */
        offset = SLP_V2_HEADER_SIZE + slpHeader2.langTagLength;

        if (offset > payloadSize) {
            return 0;
        }

        /* five string fields are defined for a request */
        if (slpHeader2.function == SrvReq) {
            uint16_t            stringLength;

            for (loop = 0; loop < 5; loop++) {
                if (offset > payloadSize) {
                    return 0;
                }
#if HAVE_ALIGNED_ACCESS_REQUIRED
                stringLength = ((*(payload + offset)) << 8) |
                               ((*(payload + offset + 1)) );
                stringLength = ntohs(stringLength);
#if YAF_ENABLE_HOOKS
                slplength[loop] = stringLength;
#endif
#else
                stringLength = ntohs(*(uint16_t *)(payload+offset));
#if YAF_ENABLE_HOOKS
                slplength[loop] = stringLength;
#endif
#endif
                /* we could get a string out here, but what would we do with
                 * it? */
# if YAF_ENABLE_HOOKS
                slpoffset[loop] = offset + sizeof(uint16_t);
#endif

                offset += sizeof (uint16_t) + stringLength;
            }

            if (offset > payloadSize) {
                return 0;
            }
        }

        /* seems likely that this might be a service location protocol, let's
         * run with that as the answer */
#if YAF_ENABLE_HOOKS
    for (loop = 0; loop < 5; loop++) {
        if ((slplength[loop] > 0) && (slplength[loop] < payloadSize)
            && (slpoffset[loop] < payloadSize))
        {
            slpStringFound = TRUE;
            yfHookScanPayload(flow, payload, slplength[loop], NULL,
                  slpoffset[loop], 92+loop, SLP_PORT_NUMBER);
        }
    }
    /* only record version and type if we have some data */
    if (slpStringFound) {
        /* version */
        yfHookScanPayload(flow, payload, sizeof(uint8_t), NULL, 0, 90,
                          SLP_PORT_NUMBER);
        /* message type */
        yfHookScanPayload(flow, payload, sizeof(uint8_t), NULL, 1, 91,
                          SLP_PORT_NUMBER);
    }
#endif

    return 1;
    }

    return 0;
}




/**
 * ycPopulateSLPV2Header
 *
 * reads bytes from a stream (byte-by-byte) to fill in a structure for the V2 SLP header
 *
 * @note it doesn't attempt to fill in the langcode field
 *
 * @param payload pointer to the payload bytes as captured from the wire
 * @param payloadSize the size of the payload array
 * @param a pointer to a srcLocProtoHeader_V2_t to populate from parsing the capture array
 *
 *
 * @return 0 on failure, non-zero on success
 */
static
unsigned int
ycPopulateSLPV2Header (
    uint8_t * payload,
    unsigned int payloadSize,
    srcLocProtoHeader_v2_t * header)
{
    uint16_t            offset = 0;
    uint8_t             readValue;
    uint8_t             readValue2;
    unsigned int        loop;


    readValue = *(payload + offset);
    offset++;
    header->version = readValue;

    if (offset > payloadSize) {
        return 0;
    }

    readValue = *(payload + offset);
    offset++;
    header->function = readValue;

    header->length = 0;
    for (loop = 0; loop < 3; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->length = (header->length << 8) | readValue;
    }



    if (offset > payloadSize) {
        return 0;
    }

    readValue = *(payload + offset);
    offset++;
    header->overflow = (readValue & 0x80) >> 7;
    header->fresh = (readValue & 0x40) >> 6;
    header->reqMcast = (readValue & 0x20) >> 5;

    if (offset > payloadSize) {
        return 0;
    }
    readValue2 = *(payload + offset);
    offset++;
    header->reserved = ((readValue & 0x1f) << 8) | (readValue2);


    header->nextExtensionOffset = 0;
    for (loop = 0; loop < 3; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->nextExtensionOffset =
          (header->nextExtensionOffset << 8) | readValue;
    }

    header->xid = 0;
    for (loop = 0; loop < 2; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->xid = (header->xid << 8) | readValue;
    }

    header->langTagLength = 0;
    for (loop = 0; loop < 2; loop++) {
        if (offset > payloadSize) {
            return 0;
        }

        readValue = *(payload + offset);
        offset++;
        header->langTagLength = (header->langTagLength << 8) | readValue;
    }

    return offset;

}
