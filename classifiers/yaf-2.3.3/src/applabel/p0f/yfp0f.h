/**
 * @internal
 *
 * @file yfpp0f.h
 *
 * Definition of the YAF interface to the passive OS fingerprinting
 * mechanism ported from p0f.
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Chris Inacio, Emily Sarneso
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


#ifndef YFPP0F_H_
#define YFPP0F_H_

#include <p0f/public.h>

/** list of different modes that the p0f
fingerprinter can operate in */
enum YFP_FIND_MODES {SYN = 0, SYNACK = 1, RST = 2, OPEN = 3};


/** structure returned from yfpPacketParse used to send into yfpFindMatch */
struct packetDecodeDetails_st {
    uint16_t        tot;
    uint8_t         df;
    uint8_t         ttl;
    uint16_t        wss;
    uint32_t        srcIp;
    uint32_t        dstIp;
    uint16_t        srcPort;
    uint16_t        dstPort;
    uint8_t         tcpOptCount;
    uint8_t         tcpOptions[MAXOPT];
    uint16_t        maxSegSize;
    uint16_t        windowScale;
    uint32_t        tcpTimeStamp;
    uint8_t         tos;
    uint32_t        quirks;
    uint32_t        synAckQuirks;
    uint32_t        rstQuirks;
    uint32_t        openQuirks;
    uint8_t         ecn;
    uint8_t        *pkt;
    uint8_t         pktLen;
    uint8_t        *payload;
    struct timeval  packetTimeStamp;
};



/**
 * yfpLoadConfig
 *
 * Loads the appropriate p0f signature definition file
 *
 *
 * @param dirname directory of the p0f database files
 * @param err glib error structure filed in on error
 *
 * @return TRUE on success, FALSE on error
 */
gboolean yfpLoadConfig(char *dirname,
    GError **err);


/**
 * yfpPacketParse
 *
 * This parses the IP & TCP layer of the packet header, it is pulling out
 * details to be used in the OS fingerprinting, and looks at various things
 * in the header that YAF doesn't otherwise care about
 *
 * @param pkt pointer to the packet data (after layer 2 removal)
 * @param pktLen length of the data in pkt
 * @param packetDetails this is the result of the parsed packet, noting all
 *                      the quirks etc used to find a rule match
 * @param err a glib error structure returned filled in on failure
 *
 * @return FALSE on error, TRUE on success
 */
gboolean yfpPacketParse (uint8_t *pkt,
    size_t pktLen,
    struct packetDecodeDetails_st *packetDetails,
    GError **err);


/**
 * yfpSynFindMatch
 *
 * called from the outside to do a finger print search on Syn packets
 *
 * @param packetDetails the decoded packet details, from the yfpPacketParse
 *        function
 * @param tryFuzzy flag to determine whether or not to use a fuzzy match
 * @param fuzzyMatch output flag, TRUE if the match was made fuzzy, FALSE for
 *        deterministic
 * @param osName pointer into a constant string, (in the matching database,)
 *        of the operating system name of the match
 * @param osDetails pointer into a constant string, (in the matching database,)
 *        of the details of the OS match (version number, comments, etc.)
 * @param osFingerPrint pointer
 * @param on error, set with a useful descriptive text string of the error that
 *        occured
 *
 * @return TRUE on success, FALSE on error
 *
 */
gboolean yfpSynFindMatch (struct packetDecodeDetails_st *packetDetails,
    gboolean tryFuzzy,
    gboolean *fuzzyMatch,
    const char **osName,
    const char **osDetails,
    char **osFingerPrint,
    GError **err);



#endif
