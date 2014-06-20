/*
 ** yafapplabel.c
 **
 ** This file implements the application labeler interface for YAF.  It
 ** allows a limited set of information about a _flow_ to captured.  It
 ** processes very packet that comes through the pipe in order to pull
 ** out its information and record flow type and details.
 **
 ** It must be enabled with a configure option to be included in YAF.
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

#if YAF_ENABLE_APPLABEL

#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include "applabel/payloadScanner.h"
#include "yafapplabel.h"

#if YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

gboolean yfAppLabelInit(
    const char      *ruleFileName,
    GError          **err)
{
    FILE *ruleFile = NULL;

    if (NULL == ruleFileName) {
        ruleFileName = YAF_CONF_DIR"/yafApplabelRules.conf";
    }

    ruleFile = fopen (ruleFileName, "r");
    if (NULL == ruleFile) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_IO, "could not open "
            "application labeler rule file \"%s\" for reading", ruleFileName);
        return FALSE;
    }

    g_debug("Initializing Rules From File: %s", ruleFileName);
    if (!ycInitializeScanRules(ruleFile, err)) {
        return FALSE;
    }

    return TRUE;
}

void yfAppLabelFlow(
    yfFlow_t *flow)
{

    if (!flow->appLabel && flow->val.paylen) {
        flow->appLabel =
            ycScanPayload(flow->val.payload, flow->val.paylen, flow,
                          &(flow->val));
    }

# if YAF_ENABLE_HOOKS
    yfHookFlowPacket(flow, &(flow->rval), flow->rval.payload,
                     flow->rval.paylen, 0, NULL, NULL);
#endif

    if (!flow->appLabel && flow->rval.paylen) {
        flow->appLabel =
            ycScanPayload(flow->rval.payload, flow->rval.paylen, flow,
                          &(flow->rval));
    }
}

#endif /*YAF_ENABLE_APPLABEL*/
