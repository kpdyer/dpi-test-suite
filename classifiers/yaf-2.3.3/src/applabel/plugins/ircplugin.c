/**
 * @internal
 *
 * @file ircplugin.c
 *
 * this provides IRC payload packet recognition for use within YAF
 * It is based on RFC 2812 and some random limited packet capture.
 *
 *
 * @author $Author$
 * @date $Date$
 * @Version $Revision$
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
#include <pcre.h>

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#define IRCDEBUG 0
#define IRC_PORT 194

/**
 * the compiled regular expressions, and related
 * flags
 *
 */
static pcre *ircMsgRegex = NULL;
static pcre *ircJoinRegex = NULL;
static pcre *ircRegex = NULL;
static pcre *ircDPIRegex = NULL;
static unsigned int pcreInitialized = 0;




/**
 * static local functions
 *
 */
static uint16_t ycIrcScanInit (void);
#if IRCDEBUG
static int ycDebugBinPrintf(uint8_t *data, uint16_t size);
#endif

/**
 * ircplugin_LTX_ycIrcScanScan
 *
 * scans a given payload to see if it conforms to our idea of what IRC traffic
 * looks like.
 *
 *
 * name abomination has been achieved by combining multiple naming standards until the prefix to
 * the function name is ircplugin_LTX_ycIrcScanScan --- it's a feature
 *
 * @param argc NOT USED
 * @param argv NOT USED
 * @param payload pointer to the payload data
 * @param payloadSize the size of the payload parameter
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 0 for no match IRC_PORT_NUMBER (194) for a match
 *
 */
uint16_t
ircplugin_LTX_ycIrcScanScan (
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{

    int rc;
#   define NUM_CAPT_VECTS 60
    int vects[NUM_CAPT_VECTS];

    if (0 == pcreInitialized) {
        if (0 == ycIrcScanInit()) {
            return 0;
        }
    }

    rc = pcre_exec(ircMsgRegex, NULL, (char *)payload, payloadSize,
                   0, 0, vects, NUM_CAPT_VECTS);
    if (rc <= 0) {
        rc = pcre_exec(ircJoinRegex, NULL, (char *)payload, payloadSize,
                       0, 0, vects, NUM_CAPT_VECTS);
    }
    if (rc <= 0) {
        rc = pcre_exec(ircRegex, NULL, (char *)payload, payloadSize,
                       0, 0, vects, NUM_CAPT_VECTS);
    }


    /** at some point in the future, this is the place to extract protocol
        information like message targets and join targets, etc.*/

#if YAF_ENABLE_HOOKS

    if (rc > 0 && ircDPIRegex) {
        yfHookScanPayload(flow, payload, payloadSize, ircDPIRegex, 0,
                          202, IRC_PORT);
    }

#endif

    if (rc > 0) {
        return IRC_PORT;
    }


    return 0;
}



/**
 * ycIrcScanInit
 *
 * this initializes the PCRE expressions needed to search the payload for
 * IRC
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is complete correctly, 0 otherwise
 */
static
uint16_t
ycIrcScanInit ()
{
    const char *errorString;
    int errorPos;

    const char ircMsgRegexString[] = "^(?:(:[^: \\n\\r]+)(?:\\ ))?"
                                     "(PRIVMSG|NOTICE) \\ "
                                     "([^: \\n\\r]+|:.*) (?:\\ )"
                                     "([^: \\n\\r]+\\ |:.*)";
    const char ircJoinRegexString[] = "^(?:(:[^\\: \\n\\r]+)(?:\\ ))?"
                                      "((JOIN) \\ "
                                      "[^: \\n\\r]+\\ |:.*)\\s";
    const char ircRegexString[] = "^((?:(:[^: \\n\\r]+)(?:\\ ))?"
                                  "(\\d{3}|PASS|OPER|QUIT|SQUIT|NICK"
                                  "|MODE|USER|SERVICE|JOIN|NAMES|INVITE"
                                  "|PART|TOPIC|LIST|KICK|PRIVMSG|NOTICE"
                                  "|MOTD|STATS|CONNECT|INFO|LUSERS|LINKS"
                                  "|TRACE|VERSION|TIME|ADMIN|SERVLIST"
                                  "|SQUERY|WHO|WHOWAS|WHOIS|KILL|PING"
                                  "|PONG|ERROR|AWAY|DIE|SUMMON|REHASH"
                                  "|RESTART|USERS|USERHOST)[ a-zA-Z0-9#]*)(?:[\r\n])";

    const char ircDPIRegexString[] = "((\\d{3}|PASS|OPER|QUIT|SQUIT|NICK"
                                     "|MODE|USER|SERVICE|JOIN|NAMES|INVITE"
                                     "|PART|TOPIC|LIST|KICK|PRIVMSG"
                                     "|MOTD|STATS|CONNECT|INFO|LUSERS|LINKS"
                                     "|TRACE|VERSION|TIME|ADMIN|SERVLIST"
                                     "|SQUERY|WHO|WHOWAS|WHOIS|KILL|PING"
                                     "|PONG|ERROR|AWAY|DIE|SUMMON|REHASH"
                                     "|RESTART|USERS|USERHOST|PROTOCTL) "
                                     "[-a-zA-Z0-9$#.:*\" ]*)(?:[\\r\\n])";

    ircRegex = pcre_compile(ircRegexString, PCRE_EXTENDED|PCRE_ANCHORED,
                            &errorString, &errorPos, NULL);
    ircMsgRegex = pcre_compile(ircMsgRegexString, PCRE_EXTENDED|PCRE_ANCHORED,
                               &errorString, &errorPos, NULL);
    ircJoinRegex = pcre_compile(ircJoinRegexString,PCRE_EXTENDED|PCRE_ANCHORED,
                                &errorString, &errorPos, NULL);
    ircDPIRegex = pcre_compile(ircDPIRegexString, PCRE_MULTILINE,
                               &errorString, &errorPos, NULL);

    if (NULL != ircRegex && NULL != ircMsgRegex && NULL != ircJoinRegex)
    {
        pcreInitialized = 1;
    }


    return pcreInitialized;
}

#if IRCDEBUG
static
int
ycDebugBinPrintf(uint8_t *data, uint16_t size)
{
    uint16_t loop;
    int numPrinted = 0;

    if (0 == size) {
        return 0;
    }

    for (loop=0; loop < size; loop++) {
        if (isprint(*(data+loop)) && !iscntrl(*(data+loop))){
            printf("%c", *(data+loop));
        } else {
            printf(".");
        }
        if ('\n' == *(data+loop) || '\r' == *(data+loop) || '\0' == *(data+loop)) {
            break;
        }
        numPrinted++;
    }

    return numPrinted;
}
#endif
