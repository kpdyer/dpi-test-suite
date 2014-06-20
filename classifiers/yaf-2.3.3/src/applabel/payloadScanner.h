/**
 * @internal
 *
 * @file playloadScanner.h
 *
 * This defines the interface to the payload scanner functions
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



#ifndef PAYLOAD_SCANNER_H_
#define PAYLOAD_SCANNER_H_

#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>

/* if this is a power of 2, then the hash used for the sparse array is (every so slightly) more efficient */
#define MAX_PAYLOAD_RULES 1024
#define LINE_BUF_SIZE 4096

typedef struct ycDnsScanMessageHeader_st {
    uint16_t            id;

    uint16_t            qr:1;
    uint16_t            opcode:4;
    uint16_t            aa:1;
    uint16_t            tc:1;
    uint16_t            rd:1;
    uint16_t            ra:1;
    uint16_t            z:1;
    uint16_t            ad:1;
    uint16_t            cd:1;
    uint16_t            rcode:4;

    uint16_t            qdcount;
    uint16_t            ancount;
    uint16_t            nscount;
    uint16_t            arcount;
} ycDnsScanMessageHeader_t;

#define DNS_PORT_NUMBER 53
#define DNS_NAME_COMPRESSION 0xc0


/**
 * ycInitializeScanRules
 *
 * @param scriptFile
 * @param err
 *
 *
 * @return FALSE if an error occurs, TRUE if there were no errors
 *
 */
gboolean            ycInitializeScanRules (
    FILE * scriptFile,
    GError ** err);

/**
 * ycScanPayload
 *
 *
 * @param payloadData
 * @param payloadSize
 * @param flow
 * @param val
 *
 * @return the value of the label of the matching rule if there is a match, otherwise 0
 *
 */
uint16_t
ycScanPayload (
    const uint8_t * payloadData,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val);


/**
 * ycDnsScanRebuildHeader
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

void         ycDnsScanRebuildHeader (
    uint8_t * payload,
    ycDnsScanMessageHeader_t * header);


#endif
