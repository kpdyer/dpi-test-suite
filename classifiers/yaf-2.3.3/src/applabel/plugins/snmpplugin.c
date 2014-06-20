/**
 * @file snmpplugin.c
 *
 *
 * This recognizes SNMP packets
 *
 * See RFC 1157 for SNMPv1
 * See RFCs 1901, 1905, 1906 for SNMPv2c
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2007-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Ecoff <ecoff@cert.org>
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


#define SNMP_PORT_NUMBER  161

/* snmp data types */
#define SNMP_INT 0x02
#define SNMP_OCT 0x04
#define SNMP_NULL 0x05
#define SNMP_OBID 0x06

/* complex data types */
#define SNMP_SEQ 0x30
#define SNMP_GETREQ 0xa0
#define SNMP_GETRES 0xa2
#define SNMP_SETREQ 0xa3


/* Local Prototypes */

uint8_t snmpGetType(uint8_t identifier);

/**
 * snmpplugin_LTX_ycSnmpScanScan
 *
 * the scanner for recognizing SNMP packets
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
 * @return SNMP_PORT_NUMBER for SNMP packets,
 *         otherwise 0
 */
uint16_t
snmpplugin_LTX_ycSnmpScanScan (
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{

    uint16_t offsetptr = 0;
    uint8_t pdu_type = 0;
    uint8_t pdu_length = 0;
    uint8_t version = 0;
    uint8_t msg_len = 0;

    if (payloadSize < 5) {
        return 0;
    }

    if (!(pdu_type = snmpGetType(payload[0]))) {
        return 0;
    }

    offsetptr++;
    /* Get length */
    pdu_length = *(payload + offsetptr);

    if (pdu_length == 0) {
        return 0;
    }

    offsetptr++;
    /* SNMP version type */
    if (*(payload + offsetptr) != SNMP_INT) {
        return 0;
    }

    offsetptr++;
    /* Should be length of 1 */
    if (*(payload + offsetptr) != 1) {
        return 0;
    }

    offsetptr++;
    /* Now at version number */
    version = *(payload + offsetptr);
    if (version == 0 || version == 1) {
        /* v1 or v2c*/
        offsetptr++;

        if (offsetptr > payloadSize) {
            return 0;
        }
        if (*(payload + offsetptr) != SNMP_OCT) {
            /* no community string */
            return 0;
        }
        offsetptr++;

        if (offsetptr > payloadSize) {
            return 0;
        }
        /* length of community string  & go past community string */
        offsetptr += *(payload + offsetptr) + 1;
        if (offsetptr > payloadSize) {
            return 0;
        }

        if (!(pdu_type = snmpGetType(*(payload + offsetptr)))) {
            return 0;
        }

        if ((pdu_type != SNMP_GETREQ) && (pdu_type != SNMP_GETRES) &&
            (pdu_type != SNMP_SETREQ))
        {
            return 0;
        }

        offsetptr++;
        if (offsetptr > payloadSize) {
            return 0;
        }
        pdu_length = *(payload + offsetptr);

        if (pdu_length == 0) {
            return 0;
        }
        offsetptr++;
        if (offsetptr > payloadSize) {
            return 0;
        }

        /* check request ID */
        if (*(payload + offsetptr) != SNMP_INT) {
            return 0;
        }

        offsetptr++;
        if (offsetptr > payloadSize) {
            return 0;
        }

        /* actual request id is here  - go past it*/
        if (*(payload + offsetptr) == 4) {
            offsetptr += 5;
        } else if (*(payload + offsetptr) == 2) {
            offsetptr += 3;
        } else if (*(payload + offsetptr) == 1) {
            offsetptr += 2;
        } else {
            return 0;
        }

        if ((offsetptr + 8) > payloadSize) {
            return 0;
        }

        /* now go to Error field */
        if (*(payload + offsetptr) != SNMP_INT) {
            return 0;
        }
        offsetptr++;
        if (*(payload + offsetptr) != 1) {
            return 0;
        }
        offsetptr++;
        /* Check Error Status code */
        if (*(payload + offsetptr) > 0x05) {
            return 0;
        }

        offsetptr++;
        /* Check Error Index */
        if (*(payload + offsetptr) != SNMP_INT) {
            return 0;
        }

        offsetptr++;
        if (*(payload + offsetptr) != 1) {
            return 0;
        }

        offsetptr += 2;
        /* Error Index is here */

        /* Next should be varbind list of type Sequence */
        if (*(payload + offsetptr) != SNMP_SEQ) {
            return 0;
        }
        offsetptr++;

        /* Length of varbind list is next */
        if (*(payload + offsetptr) == 0) {
            return 0;
        }

        /* close enough */

        return SNMP_PORT_NUMBER;

    } else if (version == 3) {
        /* version 3 fun - not there yet */
        uint8_t msg_flags = 0;

        if (offsetptr + 5 > payloadSize) {
            return 0;
        }

        offsetptr++;
        /* check for msg_max_size sequence PDU */
        if (*(payload + offsetptr) != SNMP_SEQ) {
            return 0;
        }

        offsetptr += 2;
        /* should be an integer next */
        if (*(payload + offsetptr) != SNMP_INT) {
            return 0;
        }

        offsetptr++;
        /* should be of length 4 */
        msg_len = *(payload + offsetptr);
        if (msg_len == 0) {
            return 0;
        }

        offsetptr++;
        /* msg id is here */
        offsetptr += msg_len;
        if (offsetptr > payloadSize) {
            return 0;
        }

        if (offsetptr + 4 > payloadSize) {
            return 0;
        }
        if (*(payload + offsetptr) != SNMP_INT) {
            return 0;
        }

        offsetptr++;

        /* Msg Len can be more than 2 */
        msg_len = *(payload + offsetptr);
        if (msg_len == 0) {
            return 0;
        }
        offsetptr += 1 + msg_len;

        if (offsetptr + 3 > payloadSize) {
            return 0;
        }
        /* 1 for type - 1 for length */
        if (*(offsetptr + payload) != SNMP_OCT) {
            return 0;
        }

        offsetptr++;

        msg_len = *(offsetptr + payload);
        if (msg_len == 0) {
            return 0;
        }

        offsetptr++;
        if (msg_len == 1) {
            msg_flags = *(payload + offsetptr);
            offsetptr++;

            if (msg_flags > 7) {
                return 0;
            }
        } else {
            offsetptr += msg_len;
        }

        if (offsetptr + 3 > payloadSize) {
            return 0;
        }

        /* message security model */
        if (*(offsetptr + payload) == SNMP_INT){
            offsetptr++;

            msg_len = *(payload + offsetptr);

            offsetptr += msg_len + 1;
        } else {
            return 0;
        }

        if (offsetptr + 3 > payloadSize) {
            return 0;
        }

        if (*(payload + offsetptr) != SNMP_OCT) {
            return 0;
        }
        offsetptr++;

        pdu_length = *(payload + offsetptr);
        if (pdu_length == 0) {
            return 0;
        }

        return SNMP_PORT_NUMBER;
    } else {
        return 0;
    }
}

uint8_t snmpGetType(
    uint8_t identifier)
{

    switch (identifier) {
    case SNMP_INT:
        return SNMP_INT;
    case SNMP_OCT:
        return SNMP_OCT;
    case SNMP_NULL:
        return SNMP_NULL;
    case SNMP_OBID:
        return SNMP_OBID;
    case SNMP_SEQ:
        return SNMP_SEQ;
    case SNMP_GETREQ:
        return SNMP_GETREQ;
    case SNMP_GETRES:
        return SNMP_GETRES;
    case SNMP_SETREQ:
        return SNMP_GETREQ;
    default:
        return 0;
    }
}
