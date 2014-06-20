/**
 * @INTERNAL
 *
 * @file pop3plugin.c
 *
 * this provides POP3 payload packet recognition for use within YAF
 * It is based on RFC 1939 and some random limited packet capture.
 *
 *
 * @author $Author$
 * @date $Date$
 * @Version $Revision$
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2007-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Dan Ruef <druef@cert.org>, Emily Ecoff <ecoff@cert.org>
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

#include <pcre.h>

#define POP3DEBUG 0
#define POP3_PORT 110

/**
 * the compiled regular expressions, and related
 * flags
 *
 */
static pcre *pop3ReqRegex = NULL;
static pcre *pop3RespRegex = NULL;

static unsigned int pcreInitialized = 0;


/**
 * static local functions
 *
 */

static uint16_t ycPop3ScanInit (void);
#if POP3DEBUG
static int ycDebugBinPrintf(uint8_t *data, uint16_t size);
#endif

/**
 * pop3plugin_LTX_ycPop3ScanScan
 *
 * scans a given payload to see if it conforms to our idea of what POP3 traffic
 * looks like.
 *
 *
 *
 * @param argc NOT USED
 * @param argv NOT USED
 * @param payload pointer to the payload data
 * @param payloadSize the size of the payload parameter
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 * @return 0 for no match POP3_PORT_NUMBER (110) for a match
 *
 */

uint16_t
pop3plugin_LTX_ycPop3ScanScan (
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
    uint16_t infoElement = 110;
    pcre *currentRegex = NULL;

    if (0 == pcreInitialized) {
        if (0 == ycPop3ScanInit()) {
            return 0;
        }
    }

    currentRegex = pop3ReqRegex;
    rc = pcre_exec(currentRegex, NULL, (char *)payload, payloadSize, 0,
                   0, vects, NUM_CAPT_VECTS);


    if (rc <= 0) {
        currentRegex = pop3RespRegex;
        rc = pcre_exec(currentRegex, NULL, (char *)payload,
                       payloadSize, 0, 0, vects,
                       NUM_CAPT_VECTS);
        infoElement = 111;
    }

#if YAF_ENABLE_HOOKS
    if (rc > 0){
        yfHookScanPayload(flow, payload, payloadSize, currentRegex, 0,
                          infoElement, POP3_PORT);
    }
#endif

    if ( rc > 0 ) {
        return POP3_PORT;
    }


    return 0;
}

/**
 * ycPop3ScanInit
 *
 * this initializes the PCRE expressions needed to search the payload for
 * POP3
 *
 *
 * @sideeffect sets the initialized flag on success
 *
 * @return 1 if initialization is complete correctly, 0 otherwise
 */
static
uint16_t
ycPop3ScanInit ()
{

    const char *errorString;
    int errorPos;

    const char pop3ReqRegexString[]   = "(^(?i)(QUIT|STAT|LIST|RETR|DELE|NOOP"
                                        "|RSET|TOP|UIDL|USER|PASS|APOP) "
                                        "[ a-zA-Z0-9]*)(?:[\r\n])";
    const char pop3RespRegexString[]  = "([-+](OK|ERR)[ a-zA-Z0-9]*)"
                                        "(?:[ \r\n])";


    pop3ReqRegex = pcre_compile(pop3ReqRegexString,
                                PCRE_ANCHORED, &errorString,
                                &errorPos, NULL);

    pop3RespRegex = pcre_compile(pop3RespRegexString,
                                 PCRE_ANCHORED, &errorString,
                                 &errorPos, NULL);


    if (pop3ReqRegex && pop3RespRegex) {
        pcreInitialized = 1;
    }


    return pcreInitialized;
}

#if POP3DEBUG
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
