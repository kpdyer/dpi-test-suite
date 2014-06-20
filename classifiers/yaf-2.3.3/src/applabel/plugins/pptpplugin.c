/**
 *@internal
 *
 *@file pptpplugin.c
 *
 *@brief this is a protocol classifier for the point-to-point tunneling protocol (PPTP)
 *
 * PPTPis a protocol which allows the Point to Point Protocol (PPP) to be
 * tunneled through an IP network.  PPTP describes a new vehichle for carrying
 * PPP.
 *
 * @sa rfc 2637  href="http://www.ietf.org/rfc/rfc2637.txt"
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

typedef struct pptpProtoHeader_st {
    uint16_t length;
    uint16_t msgType;
    uint32_t magicCookie;
    uint16_t controlMsgType;
    uint16_t reserved;
} pptpProtoHeader_t;

#define PPTP_PORT_NUMBER 1723
#define MAGIC_COOKIE 0x1A2B3C4D

/**
 * pptpplugin_LTX_ycPPTPScan
 *
 * returns PPTP_PORT_NUMBER if the passed in payload matches
 * a point to point tunneling protocol packet
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
pptpplugin_LTX_ycPPTPScanScan (
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{

    pptpProtoHeader_t *pptpHeader;
    uint16_t  pptpLength;
    uint16_t  pptpMsgType;
    uint32_t  pptpMagicCookie;
    uint16_t  pptpControlType;
    uint16_t  pptpReserved;

    if ( 0 == payloadSize ){
        return 0;
    }

    if (payloadSize < sizeof(pptpProtoHeader_t)){
        /*g_debug("PPTP exiting line 100");*/
        return 0;
    }

    pptpHeader = (pptpProtoHeader_t *) payload;

    pptpLength = pptpHeader->length;
    pptpMsgType = pptpHeader->msgType;
    pptpMagicCookie = pptpHeader->magicCookie;
    pptpControlType = pptpHeader->controlMsgType;
    pptpReserved = pptpHeader->reserved;

    pptpLength = ntohs(pptpLength);
    pptpMsgType = ntohs(pptpMsgType);
    pptpMagicCookie = ntohl(pptpMagicCookie);
    pptpControlType = ntohs(pptpControlType);
    pptpReserved = ntohs(pptpReserved);

    /*debug*/
    /*g_debug("PPTP Length: %d", pptpLength);
      g_debug("PPTP Length: %d", pptpMsgType);
      g_debug("PPTP Length: %d", pptpMagicCookie);
      g_debug("PPTP Length: %d", pptpControlType);
      g_debug("PPTP Length: %d", pptpReserved);
    */



    if (pptpLength <= 0){
        /*  g_debug("PPTP exiting line 105");*/
        return 0;
    }

    if (pptpReserved != 0){
        /*g_debug("PPTP exiting line 110");*/
        return 0;
    }

    if (pptpMagicCookie != MAGIC_COOKIE){
        /*g_debug("PPTP exiting line 115");*/
        return 0;
    }

    if (pptpMsgType != 1 && pptpMsgType != 2){
        /*g_debug("PPTP exiting line 120");*/
        return 0;
    }

    if (pptpControlType == 0 || pptpControlType > 15){
        /*printf("PPTP  exiting line 128");*/
        return 0;
    }

    return PPTP_PORT_NUMBER;
}
