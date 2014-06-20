/**
 *@internal
 *
 *@file tftpplugin.c
 *
 *@brief this is a protocol classifier for the Trivial File Transfer protocol (TFTP)
 *
 * TFTP is a very simple protocol used to transfer files.
 *
 * @sa rfc 1350  href="http://www.ietf.org/rfc/rfc1350.txt"
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

#include <arpa/inet.h>
#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#include <pcre.h>

#define TFTP_PORT_NUMBER 69


static pcre *tftpRegex = NULL;
static unsigned int pcreInitialized = 0;

/**
 * static local functions
 *
 */
static uint16_t ycTFTPScanInit (void);

/**
 * tftpplugin_LTX_ycTFTPScan
 *
 * returns TFTP_PORT_NUMBER if the passed in payload matches
 * a trivial file transfer protocol packet
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
tftpplugin_LTX_ycTFTPScanScan (
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{
#define NUM_CAPT_VECTS 60
    int vects[NUM_CAPT_VECTS];
    uint16_t payloadOffset = 0;
    uint8_t fileLength = 0;
    int rc;
    uint16_t tempVar;
    uint16_t opcode;

    if (0 == payloadSize) {
        return 0;
    }

    if (0 == pcreInitialized) {
        if (0 == ycTFTPScanInit()) {
            return 0;
        }
    }

    opcode = ntohs(*(uint16_t*)payload);
    payloadOffset += 2;

    if ((opcode > 5) || (opcode == 0)) {
        return 0;
    }

    if ((opcode == 1) || (opcode == 2)) {
        /* RRQ or WRQ */
        rc = pcre_exec(tftpRegex, NULL, (char *)payload, payloadSize,
                       0, 0, vects, NUM_CAPT_VECTS);
        if (rc <= 0) {
            return 0;
        }

        /* get byte offset of 1st char in substring */
        payloadOffset = vects[0];

        /* do math: payloadOffset - 2 bytes for opcode*/
        fileLength = (uint8_t)payloadOffset - 2;
        tempVar = vects[1] - vects[0];  /*len of mode*/

#if YAF_ENABLE_HOOKS
        yfHookScanPayload(flow, payload, fileLength-1, NULL,
                          (payloadOffset-fileLength), 69, TFTP_PORT_NUMBER);
        yfHookScanPayload(flow, payload, tempVar, NULL, vects[0], 70,
                          TFTP_PORT_NUMBER);
#endif
    } else if ((opcode == 3) || (opcode == 4)) {
        /* DATA or ACK packet */
        tempVar = ntohs(*(uint16_t*)(payload + payloadOffset));
        if (tempVar != 1) {
            return 0;
        }
    } else if (opcode == 5) {
        /* Error Packet */
        tempVar = ntohs(*(uint16_t*)(payload + payloadOffset));
        /* Error codes are 1-7 */
        if (tempVar > 8){
            return 0;
        }
    }

    return TFTP_PORT_NUMBER;
}



/**
 * ycTFTScanInit
 *
 * this initializes the PCRE expressions needed to search the payload for
 * TFTP
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is complete correctly, 0 otherwise
 */
static
uint16_t
ycTFTPScanInit ()
{
    const char *errorString;
    int errorPos;

    const char tftpRegexString[] = "(?:(?i)(netascii|octet|mail))";

    tftpRegex = pcre_compile(tftpRegexString, PCRE_ANCHORED, &errorString,
                             &errorPos, NULL);

    if (NULL != tftpRegex) {
        pcreInitialized = 1;
    }


    return pcreInitialized;
}
