/**
 *@internal
 *
 *@file mysqlplugin.c
 *
 *@brief this is a protocol classifier for the MySQL protocol (MySQL)
 *
 * MySQL
 *
 * @ href="http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol"
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

#define MYSQL_PORT_NUMBER 3306


/**
 * mysqlplugin_LTX_ycMYSQLScan
 *
 * returns MYSQL_PORT_NUMBER if the passed in payload matches
 * a MySQL Server Greeting packet
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
mysqlplugin_LTX_ycMYSQLScanScan (
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{

    uint16_t payloadOffset = 0;
    uint32_t fillerOffset = 0;
    int i = 0;
    uint8_t  packetNumber;
    uint32_t packetLength;
    uint8_t  protoVersion;
    uint8_t  temp;

    if (0 == payloadSize) {
        return 0;
    }

    packetLength = ((*(uint32_t *)payload)) & 0x00FFFFFF;

    payloadOffset += 3;
    if (packetLength < 49 || payloadOffset > payloadSize ||
        packetLength > payloadSize)
    {
        return 0;
    }

    packetNumber = *(payload + payloadOffset);

    payloadOffset++;

    if (packetNumber != 0 && packetNumber != 1) {
        return 0;
    }

    if (payloadOffset > payloadSize) {
        return 0;
    }

    if (packetNumber == 0) {
        /* Server Greeting */
        protoVersion = *(payload + payloadOffset);
        payloadOffset++;

        /* Version would be here - str until null*/

        /* Beginning of 0x00 fillers */
        fillerOffset = packetLength - 26 + 4;

        if (fillerOffset + 13 > payloadSize) {
            return 0;
        }

        for (i = 0; i < 13; i++) {
            temp = *(payload+fillerOffset+i);
            if (temp != 0) {
                return 0;
            }
        }
    } else {
        /* Client Authentication */
        /* Client Capabilities && Extended Capabilities*/
        payloadOffset += 4;

        /* Max Packet Size + 1 for Charset*/
        payloadOffset += 5;

        if (payloadOffset + 23 > payloadSize ) {
            return 0;
        }

        for (i = 0; i < 23; i++) {
            temp = *(payload + payloadOffset);
            if (temp != 0) {
                return 0;
            }
            payloadOffset++;
        }

#if YAF_ENABLE_HOOKS
        /* Here's the Username */
        i = 0;
        while ((payloadOffset < packetLength) &&
               (payloadOffset + i < payloadSize))
        {
            if (*(payload + payloadOffset + i)) {
                i++;
            } else {
                break;
            }
        }

        yfHookScanPayload(flow, payload, i, NULL, payloadOffset, 223,
                          MYSQL_PORT_NUMBER);

        /* Rest of pkt is password. Add 4 for pkt len & pkt num*/
        payloadOffset = packetLength + 4;

        if (packetLength > payloadSize) {
            return MYSQL_PORT_NUMBER;
        }

        /* Check for more packets */
        while (payloadOffset < payloadSize) {

            packetLength=(*(uint32_t *)(payload + payloadOffset)) & 0x00FFFFFF;

            if (packetLength > payloadSize) {
                return MYSQL_PORT_NUMBER;
            }

            payloadOffset += 4; /* add one for packet number */

            if (payloadOffset > payloadSize || packetLength == 0) {
                return MYSQL_PORT_NUMBER;
            }

            packetNumber = *(payload + payloadOffset);

            payloadOffset++;

            /* The text of the command follows */
            i = (packetLength - 1);

            if (payloadOffset + i > payloadSize) {
                return MYSQL_PORT_NUMBER;
            }

            yfHookScanPayload(flow, payload, i, NULL, payloadOffset,
                              packetNumber,
                              MYSQL_PORT_NUMBER);

            payloadOffset += i;

        }

#endif
    }

    return MYSQL_PORT_NUMBER;
}
