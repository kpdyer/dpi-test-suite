/**
 * @internal
 *
 * @file payloadScanner.c
 *
 * these functions read the playload scanning rules and then also
 * have a function to be called to process those rules
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

#if YAF_ENABLE_APPLABEL

#include <ctype.h>
#include <pcre.h>
#include <ltdl.h>
#include <search.h>
#include <stdlib.h>
#include "portHash.h"
#include "payloadScanner.h"

#ifdef YAF_ENABLE_HOOKS
#include <yaf/yafhooks.h>
#endif

#ifndef YFDEBUG_APPLABEL
#define YFDEBUG_APPLABEL 0
#endif

#define YAF_SEARCH_PATH "/usr/local/lib/yaf"

typedef uint16_t (*ycScannerPlugin_fn) (
    int argc,
    char *argv[],
    const uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val);

typedef struct payloadScanRule_st {
    uint16_t            payloadLabelValue;
    enum { REGEX, PLUGIN, EMPTY, SIGNATURE } ruleType;
    union {
        struct {
            pcre               *scannerExpression;
            pcre_extra         *scannerExtra;

        } regexFields;
        struct {
            /* ala argc, argv */
            int                 numArgs;
            char              **pluginArgs;
            lt_dlhandle         handle;
            ycScannerPlugin_fn  func;
        } pluginArgs;
    } ruleArgs;
} payloadScanRule_t;


/* this is used for PCRE when compiling rules,
 * it is the size of the error string
*/
#define ESTRING_SIZE 512
#define NETBIOS_PORT 137
/* max capture length for each DPI field */
#define MAX_CAPTURE_LENGTH 50

/**
 *
 * file globals
 *
 */
static payloadScanRule_t ruleTable[MAX_PAYLOAD_RULES];
static unsigned int numPayloadRules = 0;
static payloadScanRule_t sigTable[MAX_PAYLOAD_RULES];
static unsigned int numSigRules = 0;


/**
 *
 * local functions
 *
 */
static void         ycDisplayScannerRuleError (
    char *eString,
    unsigned int size,
    const char *descrip,
    const char *errorMsg,
    const char *regex,
    int errorPos);

static void         ycChunkString (
    const char *sampleString,
    int *argNum,
    char **argStrings[]);

#if YFDEBUG_APPLABEL
static void         ycPayloadPrinter (
    uint8_t * payloadData,
    unsigned int payloadSize,
    unsigned int numPrint,
    const char *prefixString);
#endif


/**
 * initializeScanRules
 *
 * this reads in the rules definition file for identifying the playload.
 * It compiles the regular
 * expressions and loads in the dynamic libraries as defined for later use
 *
 * @param scriptFile a file pointer to the rule definition file
 *
 */
gboolean
ycInitializeScanRules (
    FILE * scriptFile,
    GError ** err)
{
/*
// for every rule that is "imagined" can be returned on a single call to
   pcre_exec, you need to multiply that number by 6 for the correct number of
   "vector" entries (and because of pcre limitation should be a multiple of 3)
*/
#define NUM_SUBSTRING_VECTS 60
    const char         *errorString;
    int                 errorPos;

    char                eString[ESTRING_SIZE];
    pcre               *ruleScanner;
    pcre               *pluginScanner;
    pcre               *commentScanner;
    pcre               *pluginArgScanner;
    pcre               *signatureScanner;
    const char          commentScannerExp[] = "^\\s*#[^\\n]*\\n";
    const char          pluginScannerExp[] =
      "^[[:space:]]*label[[:space:]]+([[:digit:]]+)"
      "[[:space:]]+plugin[[:space:]]*([^[:space:]\\n].*)\\n";
    const char          ruleScannerExp[] =
      "^[[:space:]]*label[[:space:]]+([[:digit:]]+)"
      "[[:space:]]+regex[[:space:]]*([^\\n].*)\\n";
    const char          signatureScannerExp[] =
      "^[[:space:]]*label[[:space:]]+([[:digit:]]+)"
      "[[:space:]]+signature[[:space:]]*([^\\n].*)\\n";
    const char          pluginArgScannerExp[] = "[[:word:]]";
    int                 rc;
    int                 substringVects[NUM_SUBSTRING_VECTS];
    char                lineBuffer[LINE_BUF_SIZE];
    int                 readLength;
    char               *captString;
    unsigned int        bufferOffset = 0;
    int                 currentStartPos = 0;
    int                 loop;
    char                *ltdl_lib_path = NULL;

    /* first mark all plugin entries as empty, just in case */
    for (loop = 0; loop < MAX_PAYLOAD_RULES; loop++) {
        ruleTable[loop].ruleType = EMPTY;
    }

    /* initialize the hash table */
    ycPortHashInitialize();


    /* initialize the dynamic loader library */
    rc = lt_dlinit();
    if (0 != rc) {
        *err = g_error_new (YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                     "error initializing the dynamic loader library: \"%s\"",
                     lt_dlerror ());
        return FALSE;
    }

    /* if LTDL_LIBRARY_PATH is set - add this one first */
    ltdl_lib_path = getenv("LTDL_LIBRARY_PATH");
    if (ltdl_lib_path) {
        lt_dladdsearchdir(ltdl_lib_path);
    }

    /* add /usr/local/lib/yaf to path since libtool can never find it */

    lt_dladdsearchdir(YAF_SEARCH_PATH);

    /* create the hash table for library modules to library handle names */
    if (!hcreate ((MAX_PAYLOAD_RULES * 20) / 100)) {
        *err = g_error_new (YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                     "couldn't create load module hash table (%d)", errno);
        return FALSE;
    }


    /*
     * take all of the rules needed to parse the rule file and compile
     * them into a form that // the regular expression engine can deal with */
    ruleScanner = pcre_compile(ruleScannerExp, PCRE_MULTILINE, &errorString,
                               &errorPos, NULL);
    if (NULL == ruleScanner) {
        ycDisplayScannerRuleError(eString, ESTRING_SIZE,
                                  "couldn't build the rule scanner",
                                  errorString, ruleScannerExp, errorPos);
        *err = g_error_new(YAF_ERROR_DOMAIN,YAF_ERROR_INTERNAL, "%s", eString);
        return FALSE;
    }

    pluginScanner = pcre_compile(pluginScannerExp, PCRE_MULTILINE,
                                 &errorString, &errorPos, NULL);
    if (NULL == pluginScanner) {
        ycDisplayScannerRuleError(eString, ESTRING_SIZE,
                                  "couldn't build the plugin scanner",
                                  errorString, pluginScannerExp, errorPos);
        *err = g_error_new(YAF_ERROR_DOMAIN,YAF_ERROR_INTERNAL, "%s", eString);
        return FALSE;
    }

    commentScanner = pcre_compile(commentScannerExp, PCRE_MULTILINE,
                                  &errorString, &errorPos, NULL);
    if (NULL == commentScanner) {
        ycDisplayScannerRuleError (eString, ESTRING_SIZE,
                                   "couldn't build the comment scanner",
                                   errorString, commentScannerExp, errorPos);
        *err = g_error_new(YAF_ERROR_DOMAIN,YAF_ERROR_INTERNAL, "%s", eString);
        return FALSE;
    }

    pluginArgScanner = pcre_compile(pluginArgScannerExp, PCRE_MULTILINE,
                                    &errorString, &errorPos, NULL);
    if (NULL == pluginArgScanner) {
        ycDisplayScannerRuleError(eString, ESTRING_SIZE,
                                  "couldn't build the plugin argument scanner",
                                  errorString, pluginArgScannerExp, errorPos);
        *err = g_error_new(YAF_ERROR_DOMAIN,YAF_ERROR_INTERNAL, "%s", eString);
        return FALSE;
    }

    signatureScanner = pcre_compile(signatureScannerExp, PCRE_MULTILINE,
                                    &errorString, &errorPos, NULL);
    if (NULL == signatureScanner) {
        ycDisplayScannerRuleError (eString, ESTRING_SIZE,
                       "couldn't build the signature scanner",
                       errorString, signatureScannerExp, errorPos);
        *err = g_error_new(YAF_ERROR_DOMAIN,YAF_ERROR_INTERNAL, "%s", eString);
        return FALSE;
    }

    /*
     * this is the loop that does the lion's share of the rule file
     * processing first read a hunk of the rule file, (this may include
     * multiple lines of stuff) this gets a little bit ugly, there are a
     * number of issues that have to handled; first, because there may be
     * multiple lines (which is in fact likely) it has to be able to work
     * its way through the buffer, a single pass of the buffer through the
     * pcre engine simply won't cut it; at the end, it is possible // to have
     * part of line, when this happens, it needs to copy the leftover part
     * of the read into the front of the buffer, and then read again to fill in
     * the rest of line.  (this detail limits a single line to
     * LINE_BUF_SIZE size) */
    do {
        readLength =
          fread (lineBuffer + bufferOffset, 1, LINE_BUF_SIZE - 1 -bufferOffset,
                 scriptFile);
        if (0 == readLength) {
            if (ferror (scriptFile)) {
                *err = g_error_new (YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                             "couldn't read the rule file: %s",
                             strerror (errno));
                return FALSE;
            }
            break;
        }

        /* fread only returns how much it read from the file - need to add
           extra we put in the buffer from last read, if any */

        readLength += bufferOffset;

        /*
         * substringVects is used by the pcre library to indicate where the
         * matched substrings are in the input string, but [1] points to
         * the very end of the total match, we use this to iterate through
         * the readBuffer, always reset it after a read */
        substringVects[0] = 0;
        substringVects[1] = 0;

        /* parse as much of the input buffer as possible */
        while (substringVects[1] < readLength) {

#if YFDEBUG_APPLABEL
            g_debug("readLength %d startPosition %d\n", readLength,
                    substringVects[1]);
            for (loop=0; loop < 10; loop++) {
                if (loop+substringVects[1] > readLength) {
                    break;
                }
                char curChar = *(lineBuffer + substringVects[1] + loop);
                if (iscntrl(curChar)) {
                    g_debug(".");
                    continue;
                }
                if (isprint(curChar)) {
                    g_debug("%c", curChar);
                } else {
                    g_debug(".");
                }
            }
            g_debug("\n");
#endif
            /* get rid of CR's and LF's at the begging, use the simple manual
             * method, they gum up the regex works */
            if ('\n' == *(lineBuffer + substringVects[1])
                || '\r' == *(lineBuffer + substringVects[1])) {
                substringVects[1]++;
                continue;
            }

            /* first check for comments, and eliminate them */
            currentStartPos = substringVects[1];
            /* need to store the current offset, if we fail to match, we
               get -1 in [1] */
            rc = pcre_exec (commentScanner, NULL, lineBuffer, readLength,
                            substringVects[1], PCRE_ANCHORED, substringVects,
                            NUM_SUBSTRING_VECTS);
            if (rc > 0) {
#if YFDEBUG_APPLABEL
                g_debug("comment match pos %d to pos %d\n",
                    substringVects[0], substringVects[1]);
                pcre_get_substring(lineBuffer, substringVects, rc, 0,
                    (const char**)&captString);
                g_debug("comment line is \"%s\"\n", captString);
                pcre_free(captString);
#endif
                continue;
            }
            substringVects[1] = currentStartPos;

            /* scan the line to see if it is a regex statement, and get the
             * arguments if it is */
            rc = pcre_exec (ruleScanner, NULL, lineBuffer, readLength,
                            substringVects[1], PCRE_ANCHORED, substringVects,
                            NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                pcre               *newRule;
                pcre_extra         *newExtra;

                /* get the first matched field from the regex rule expression
                 * (the label value) */
                pcre_get_substring (lineBuffer, substringVects, rc, 1,
                                    (const char **) &captString);
                ruleTable[numPayloadRules].payloadLabelValue =
                  strtoul (captString, NULL, 10);
#if YFDEBUG_APPLABEL
                g_debug("regex: rule # %u, label value %lu ",
                        numPayloadRules, strtoul(captString, NULL, 10));
#endif
                pcre_free (captString);

                /* get the second matched field from the regex rule expression
                 * (should be the regex) */

                pcre_get_substring(lineBuffer, substringVects, rc, 2,
                                   (const char **) &captString);
#if YF_DEBUG_APPLABEL
                g_debug(" regex \"%s\"\n", captString);
#endif
                newRule = pcre_compile(captString, 0, &errorString, &errorPos,
                                       NULL);
                if (NULL == newRule) {
                    ycDisplayScannerRuleError(eString, ESTRING_SIZE,
                                     "error in regex application labeler rule",
                                              errorString, captString,
                                              errorPos);

                } else {
                    newExtra = pcre_study (newRule, 0, &errorString);
                    ruleTable[numPayloadRules].ruleArgs.regexFields.
                      scannerExpression = newRule;
                    ruleTable[numPayloadRules].ruleArgs.regexFields.
                      scannerExtra = newExtra;
                    ruleTable[numPayloadRules].ruleType = REGEX;
                    ycPortHashInsert(ruleTable[numPayloadRules].payloadLabelValue, numPayloadRules);
                    numPayloadRules++;
                }
                pcre_free (captString);

                if (MAX_PAYLOAD_RULES == numPayloadRules) {
                    *err = g_error_new (YAF_ERROR_DOMAIN, YAF_ERROR_LIMIT,
                                        "maximum number of application labeler"
                                        " rules has been reached");
                    return FALSE;
                }

                continue;
            }
            substringVects[1] = currentStartPos;
            /* scan the line to see if it is a plugin statement, and handle the
             * arguments if it is */
            rc = pcre_exec (pluginScanner, NULL, lineBuffer, readLength,
                            substringVects[1], PCRE_ANCHORED, substringVects,
                            NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                int                 numArgs;
                char             **argStrings;

                /* get the first matched field from the regex rule expression
                 * (the lable value) */
                pcre_get_substring (lineBuffer, substringVects, rc, 1,
                                    (const char **) &captString);
                ruleTable[numPayloadRules].payloadLabelValue =
                  strtoul (captString, NULL, 10);
#if YFDEBUG_APPLABEL
                g_debug("plugin: rule # %u, label value %lu ",
                        numPayloadRules, strtoul(captString, NULL, 10));
#endif
                pcre_free (captString);

                /*
                 * get the second matched field, which should be the plugin
                 * name and all of its arguments, now we need to chunk that
                 * into an array of strings, ala argc, argv
                 */
                pcre_get_substring(lineBuffer, substringVects, rc, 2,
                                   (const char **) &captString);
                ycChunkString(captString, &numArgs, &argStrings);

                if (numArgs < 2) {
                    g_critical("error: not enough arguments to load and call "
                               "a plugin, at least a library name and function"
                               " name are needed\n");
                    pcre_free (captString);
                    pcre_get_substring (lineBuffer, substringVects, rc, 0,
                                        (const char **) &captString);
                    g_critical ("input line: \"%s\"\n", captString);
                } else {
                    ENTRY               newItem;
                    ENTRY              *foundItem;
                    lt_dlhandle         modHandle;
                    lt_ptr              funcPtr;

                    ruleTable[numPayloadRules].ruleType = PLUGIN;
                    ruleTable[numPayloadRules].ruleArgs.pluginArgs.numArgs =
                      numArgs;
                    ruleTable[numPayloadRules].ruleArgs.pluginArgs.pluginArgs =
                      argStrings;

                    newItem.key = strdup(argStrings[0]);
                    if (NULL == newItem.key) {
                        g_error ("out of memory error\n");
                        for (loop = 0; loop < numArgs; loop++) {
                            free ((char *) (argStrings[loop]));
                        }
                        free(argStrings);
                        return FALSE;
                    }
                    newItem.data = NULL;
                    foundItem = hsearch (newItem, FIND);
                    if (NULL == foundItem) {

                        modHandle = lt_dlopenext (newItem.key);
                        if (NULL == modHandle) {
                            g_critical ("couldn't open library \"%s\": %s\n",
                                        argStrings[0], lt_dlerror ());
                            for (loop = 0; loop < numArgs; loop++) {
                                free ((char *) (argStrings[loop]));
                            }
                            free (argStrings);
                            pcre_free (captString);
                            continue;
                        }
                        newItem.data = (void *) modHandle;
                        hsearch (newItem, ENTER);
                    } else {
                        modHandle = (lt_dlhandle)foundItem->data;
                    }

                    funcPtr = lt_dlsym (modHandle, argStrings[1]);
                    if (NULL == funcPtr) {
                        g_critical("couldn't find function \"%s\" in library"
                                   " \"%s\"\n", argStrings[1], argStrings[0]);
                        for (loop = 0; loop < numArgs; loop++) {
                            free ((char *) (argStrings[loop]));
                        }
                        free (argStrings);
                        pcre_free (captString);
                        continue;
                    }
                    ruleTable[numPayloadRules].ruleArgs.pluginArgs.func =
                        (ycScannerPlugin_fn) funcPtr;

                    ycPortHashInsert(ruleTable[numPayloadRules].payloadLabelValue, numPayloadRules);
                    numPayloadRules++;
                }

                pcre_free (captString);

                if (MAX_PAYLOAD_RULES == numPayloadRules) {
                    g_warning ("maximum number of rules has been reached\n");
                    return TRUE;
                }
                continue;
            }


        substringVects[1] = currentStartPos;

        /* scan the line to see if it is a signature, and get the
         * arguments if it is */
        rc = pcre_exec(signatureScanner, NULL, lineBuffer, readLength,
                       substringVects[1], PCRE_ANCHORED, substringVects,
                       NUM_SUBSTRING_VECTS);
        if (rc > 0) {
            pcre               *newRule;
            pcre_extra         *newExtra;

            /* get the first matched field from the regex rule expression
             * (the label value) */
            pcre_get_substring(lineBuffer, substringVects, rc, 1,
                               (const char **) &captString);

            sigTable[numSigRules].payloadLabelValue = strtoul(captString, NULL,
                                                              10);
#if YFDEBUG_APPLABEL
            g_debug("signature: rule # %u, label value %lu ",
                    numSigRules, strtoul(captString, NULL, 10));
#endif
            pcre_free (captString);

            /* get the second matched field from the regex rule expression
             * (should be the regex) */
            pcre_get_substring(lineBuffer, substringVects, rc, 2,
                               (const char **) &captString);
#if YFDEBUG_APPLABEL
            g_debug(" signature \"%s\"\n", captString);
#endif
            newRule = pcre_compile(captString, 0, &errorString, &errorPos,
                                   NULL);
            if (NULL == newRule) {
                ycDisplayScannerRuleError (eString, ESTRING_SIZE,
                                           "error in signature application "
                                           "labeler rule", errorString,
                                           captString, errorPos);

            } else {
                newExtra = pcre_study (newRule, 0, &errorString);
                sigTable[numSigRules].ruleArgs.regexFields.
                    scannerExpression = newRule;
                sigTable[numSigRules].ruleArgs.regexFields.
                    scannerExtra = newExtra;
                sigTable[numSigRules].ruleType = SIGNATURE;
                numSigRules++;
            }

            pcre_free(captString);

            if (MAX_PAYLOAD_RULES == numSigRules) {
                *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_LIMIT,
                                   "maximum number of signature rules has "
                                   "been reached");
                return FALSE;
            }

            continue;
        }

        substringVects[1] = currentStartPos;


        /*   pcre_free (captString);*/

#if YFDEBUG_APPLABEL
        g_debug("plugin args: ");
        for (loop = 0; loop < numArgs; loop++) {
            g_debug("\"%s\" ", (*argStrings)[loop]);
        }
        g_debug("\n");
#endif

        /*
         * check to see if we have partial text left over at the end of
         * the read buffer, if we copy it to the front of the read
         * buffer, and on the next read, read a little less to
         * compensate for the left over amount */
        if ((PCRE_ERROR_NOMATCH == rc) && (substringVects[1] < readLength)
            && !feof (scriptFile)) {
            memmove (lineBuffer, lineBuffer + substringVects[1],
                     readLength - substringVects[1]);
            bufferOffset = readLength - substringVects[1];
            break;
        } else if (PCRE_ERROR_NOMATCH == rc && feof (scriptFile)) {
            /* this is an error, we have crap left over at the end of the
             * file that we can't parse! */
            g_critical("unparsed text at the end of the application labeler"
                       " rule file!\n");
            break;
        }
        }

    } while (!ferror (scriptFile) && !feof (scriptFile));

    /*
     * get rid of the module handle lookup hash; this creates a mem leak of
     * the module handles, they can't be freed any longer (although this is a
     * crappy hash, and iterating the hash is not possible....) */
    hdestroy ();

    g_debug("Application Labeler accepted %d rules.", numPayloadRules);
    g_debug("Application Labeler accepted %d signatures.", numSigRules);

    pcre_free(ruleScanner);
    pcre_free(pluginScanner);
    pcre_free(commentScanner);
    pcre_free(pluginArgScanner);
    pcre_free(signatureScanner);

    /* debug */
    return TRUE;
}




/**
 * scanPayload
 *
 * this iterates through all of the defined payload identifiers, as needed,
 * to determine what the payload type is.  It stops on the first match,
 *  so ordering does matter
 *
 * @param payloadData a pointer into the payload body
 * @param payloadSize the size of the payloadData in octects (aka bytes)
 *
 * @return a 16-bit int, usually mapped to a well known port, identifying
 *         the protocol, 0 if no match was found or any type of error occured
 *         during processing
 */
uint16_t
ycScanPayload (
    const uint8_t * payloadData,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{
#define NUM_CAPT_VECTS 18
    unsigned int        loop = 0;
    int                 rc = 0;
    int                 captVects[NUM_CAPT_VECTS];
    uint16_t            dstPort;
    uint16_t            srcPort;


    srcPort = flow->key.sp; /* source port */
    dstPort = flow->key.dp; /* destination port */

    /* ycPayloadPrinter(payloadData, payloadSize, 500, "/t");*/
    /* first check the signature table to see if any signatures should
     * be executed first  - check both directions and only check once*/
    if ( numSigRules > 0 && (val == &(flow->val))) {
        for (loop = 0; loop < numSigRules; loop++) {
            rc = pcre_exec(sigTable[loop].ruleArgs.regexFields.scannerExpression,
                    sigTable[loop].ruleArgs.regexFields.scannerExtra,
                    (char *) payloadData, payloadSize, 0, 0, captVects,
                    NUM_CAPT_VECTS);

            if (rc > 0) {
                /* Found a signature match */
                return sigTable[loop].payloadLabelValue;
            }
            if (flow->rval.paylen) {
                rc = pcre_exec (sigTable[loop].ruleArgs.regexFields.scannerExpression,
                        sigTable[loop].ruleArgs.regexFields.scannerExtra,
                        (char *) flow->rval.payload, flow->rval.paylen, 0, 0,
                        captVects, NUM_CAPT_VECTS);
                if (rc > 0) {
                    /* Found a signature match on reverse direction */
                    return sigTable[loop].payloadLabelValue;
                }
            }
        }
    }

    /* next check for a rule table match based on the ports, if there isn't a
     * match, then exhaustively try all the rules in definition order */
    if ((MAX_PAYLOAD_RULES + 1) != (loop = ycPortHashSearch (srcPort))) {
        if (REGEX == ruleTable[loop].ruleType) {
            rc =
             pcre_exec(ruleTable[loop].ruleArgs.regexFields.scannerExpression,
                       ruleTable[loop].ruleArgs.regexFields.scannerExtra,
                       (char *) payloadData, payloadSize, 0, 0, captVects,
                       NUM_CAPT_VECTS);
        } else if (PLUGIN == ruleTable[loop].ruleType) {
            rc =
                ruleTable[loop].ruleArgs.pluginArgs.func(ruleTable[loop].
                                                         ruleArgs.pluginArgs.
                                                         numArgs,
                                                         ruleTable[loop].
                                                         ruleArgs.pluginArgs.
                                                         pluginArgs,
                                                         payloadData,
                                                         payloadSize,
                                                         flow, val);

        }
    } else if ((MAX_PAYLOAD_RULES + 1) != (loop = ycPortHashSearch (dstPort)))
    {
        if (REGEX == ruleTable[loop].ruleType) {
            rc =
                pcre_exec (ruleTable[loop].ruleArgs.regexFields.scannerExpression,
                           ruleTable[loop].ruleArgs.regexFields.scannerExtra,
                           (char *) payloadData, payloadSize, 0, 0, captVects,
                           NUM_CAPT_VECTS);
        } else if (PLUGIN == ruleTable[loop].ruleType) {
            rc =
                ruleTable[loop].ruleArgs.pluginArgs.func (ruleTable[loop].
                                                          ruleArgs.pluginArgs.
                                                          numArgs,
                                                          ruleTable[loop].
                                                          ruleArgs.pluginArgs.
                                                          pluginArgs,
                                                          payloadData,
                                                          payloadSize,
                                                          flow, val);
            if (rc > 0) {
                if (rc == 1) {
                    return ruleTable[loop].payloadLabelValue;
                } else {
                    return rc;
                }
            }

        }
    }

    if (rc > 0) {
#if YFDEBUG_APPLABEL
        g_debug("protocol match (%u, %u): \"",
                ruleTable[loop].payloadLabelValue, rc);
        ycPayloadPrinter(payloadData, payloadSize, 20, "\t");
#endif
        return ruleTable[loop].payloadLabelValue;
    }


    for (loop = 0; loop < numPayloadRules; loop++) {
        if (REGEX == ruleTable[loop].ruleType) {
            rc =
              pcre_exec(ruleTable[loop].ruleArgs.regexFields.scannerExpression,
                         ruleTable[loop].ruleArgs.regexFields.scannerExtra,
                         (char *) payloadData, payloadSize, 0, 0, captVects,
                         NUM_CAPT_VECTS);
            if (rc > 0) {
#if YFDEBUG_APPLABEL
                g_debug("protocol match (%u, %u): \"",
                        ruleTable[loop].payloadLabelValue, rc);
                ycPayloadPrinter(payloadData, payloadSize, 20, "\t");
#endif
                return ruleTable[loop].payloadLabelValue;
            }
        } else if (PLUGIN == ruleTable[loop].ruleType) {
            rc =
                ruleTable[loop].ruleArgs.pluginArgs.func (ruleTable[loop].
                                                          ruleArgs.pluginArgs.
                                                          numArgs,
                                                          ruleTable[loop].
                                                          ruleArgs.pluginArgs.
                                                          pluginArgs,
                                                          payloadData,
                                                          payloadSize,
                                                          flow, val);
            if (rc > 0) {
#if YFDEBUG_APPLABEL
                g_debug("protocol match (%u, %u): \"",
                        ruleTable[loop].payloadLabelValue, rc);
                ycPayloadPrinter(payloadData, payloadSize, 20, "\t");
#endif
                /* If plugin returns 1 -
                   return whatever value is in the conf file */
                /* Plugins can identify more than 1 type of protocol */
                if (rc == 1) {
                   return ruleTable[loop].payloadLabelValue;
                } else {
                    return rc;
                }
            }
        }
    }


#if YFDEBUG_APPLABEL
    if (NULL != payloadData) {
        ycPayloadPrinter(payloadData, payloadSize, 40,
                         "non-matching payload data is");
    } else {
        g_debug("no payload present\n");
    }
#endif

    return 0;

}

#if YFDEBUG_APPLABEL
/**
 * ycPayloadPrinter
 *
 * this is used for debug purposes to print out the start of the payload data,
 * useful in checking if the app labeler is getting anything correct when adding
 * new protocols
 *
 * @param payloadData a pointer to the payload array
 * @param payloadSize the size of the payloadData array
 * @param numPrint amount of the payload data to print
 * @param prefixString string to add to the front of the payload dump
 *
 */
static
void
ycPayloadPrinter (
    uint8_t * payloadData,
    unsigned int payloadSize,
    unsigned int numPrint,
    const char * prefixString)
{
#define PAYLOAD_PRINTER_ARRAY_LENGTH 4096
    unsigned int        loop;
    char                dumpArray[PAYLOAD_PRINTER_ARRAY_LENGTH];
    char                *arrayIndex;

    if ((numPrint + strlen(prefixString)) > PAYLOAD_PRINTER_ARRAY_LENGTH) {
        return;
    }

    strcpy(dumpArray, prefixString);
    arrayIndex = dumpArray + strlen(prefixString);
    snprintf(arrayIndex,
             (PAYLOAD_PRINTER_ARRAY_LENGTH - (arrayIndex-dumpArray)),
             ": \"");
    arrayIndex += strlen(": \"");

    if (NULL != payloadData) {
        for (loop = 0; loop < numPrint; loop++) {
            if (loop > payloadSize) {
                break;
            }
            if (isprint (*(payloadData + loop)) &&
                !iscntrl(*(payloadData + loop)))
            {
                snprintf(arrayIndex,
                         (PAYLOAD_PRINTER_ARRAY_LENGTH-(arrayIndex-dumpArray)),
                         "%c", *(payloadData + loop));
                arrayIndex++;
            } else {
                snprintf(arrayIndex,
                         (PAYLOAD_PRINTER_ARRAY_LENGTH-(arrayIndex-dumpArray)),
                         ".");
                arrayIndex++;
            }
        }
        snprintf(arrayIndex, (PAYLOAD_PRINTER_ARRAY_LENGTH -
                              (arrayIndex-dumpArray)), "\"");
        arrayIndex += strlen("\"");
    }

    g_debug("%s", dumpArray);

}
#endif


/**
 * ycDisplayScannerRuleError
 *
 * displays an error line to the user when a scanner rule (used for the built in rules too) doesn't compile
 * using the PCRE lirbary
 *
 * @param eString the string array to put the formatted error string,
 *        memory allocated by caller
 * @param size the length of the eString
 * @param descrip a brief description prefixed before the error output
 * @param errorMsg the error message returned from the PCRE library
 * @param regex the regular expression passed into PCRE compile
 * @param errorPos the position where the expression failed (returned from pcre_compile)
 *
 */
static
  void
ycDisplayScannerRuleError (
    char *eString,
    unsigned int size,
    const char *descrip,
    const char *errorMsg,
    const char *regex,
    int errorPos)
{
    unsigned int        offset = 0;
    unsigned int        amountLeft = size;
    unsigned int        sizeOut;
    unsigned int        loop;

    sizeOut =
      snprintf(eString + offset, amountLeft, "%s\n\t%s\n", descrip, errorMsg);
    amountLeft -= sizeOut;
    offset += sizeOut;
    sizeOut = snprintf(eString + offset, amountLeft, "\tregex: %s\n", regex);
    amountLeft -= sizeOut;
    offset += sizeOut;
    sizeOut = snprintf(eString + offset, amountLeft, "\terror: ");
    amountLeft -= sizeOut;
    offset += sizeOut;
    for (loop = 0; loop < errorPos; loop++) {
        sizeOut = snprintf (eString + offset, amountLeft, " ");
        amountLeft -= sizeOut;
        offset += sizeOut;
    }

    snprintf(eString + offset, amountLeft, "^\n");

}


/**
 * ycChunkString
 *
 * this turns a single string buffer (char *) into a set of seperate
 * words, it does this to convert an argument list as a single parameter
 * to return something that looks like the standard C argc, argv pair
 *
 * @param sampleString the input string, with multiple words as a single
 *        input buffer
 * @param argNum on output the number of arguments split out from
 *        sampleString; 0 on error or no arguments
 * @param argStrings an array of strings allocated dynamically here and
 *        returned that contains each space seperated word in the
 *        sampleString
 *
 * @note This function allocates memory that it does not free!
 *
 */
static
  void
ycChunkString (
    const char *sampleString,
    int *argNum,
    char **argStrings[])
{
    pcre               *wordScanner;
    char                wordScannerExp[] = "[^ \t\n]+";
    const char         *errorString;
    int                 errorPos;
    int                 substringVects[NUM_SUBSTRING_VECTS];
    char               *captString;
    int                 rc;
    unsigned int        loop;

    char                eString[ESTRING_SIZE];

    /* compile the regex scanner to find the words */
    wordScanner =
      pcre_compile (wordScannerExp, 0, &errorString, &errorPos, NULL);
    if (NULL == wordScanner) {
        ycDisplayScannerRuleError (eString, ESTRING_SIZE,
                                   "failed to compile the word scanner??",
                                   errorString, wordScannerExp, errorPos);
        *argNum = 0;
        return;
    }

    /*
     * first step: find all of the strings, and count how many of them there
     * are (then we can allocate memory) for each of them in a second pass
     * :( */
    substringVects[0] = 0;
    substringVects[1] = 0;
    *argNum = 0;
    do {
        rc =
          pcre_exec (wordScanner, NULL, sampleString, strlen (sampleString),
                     substringVects[1], 0, substringVects, NUM_SUBSTRING_VECTS);
        if (rc > 0) {
            pcre_get_substring (sampleString, substringVects, rc, 0,
                                (const char **) &captString);
            (*argNum)++;
            pcre_free (captString);
        }
    } while (rc > 0);


    /* allocate an array of char[] pointers (char **) */
    *argStrings = (char **) malloc (*argNum * sizeof (char *));

    /* now that we have memory to store all the strings, find them all (again) */
    substringVects[0] = 0;
    substringVects[1] = 0;
    for (loop = 0; loop < *argNum; loop++) {
        rc =
          pcre_exec (wordScanner, NULL, sampleString, strlen (sampleString),
                     substringVects[1], 0, substringVects, NUM_SUBSTRING_VECTS);
        pcre_get_substring (sampleString, substringVects, rc, 0,
                            (const char **) &captString);
        (*argStrings)[loop] =
          malloc (sizeof (char) * (strlen (captString) + 1));
        strcpy ((*argStrings)[loop], captString);
        pcre_free (captString);
    }

    pcre_free(wordScanner);
}


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
void
ycDnsScanRebuildHeader (
    uint8_t * payload,
    ycDnsScanMessageHeader_t * header)
{
    uint16_t           *tempArray = (uint16_t *) header;
    uint16_t            bitmasks = ntohs (*((uint16_t *) (payload + 2)));
    unsigned int        loop;

    memcpy (tempArray, payload, sizeof (ycDnsScanMessageHeader_t));
    for (loop = 0; loop < sizeof (ycDnsScanMessageHeader_t) / sizeof (uint16_t);
         loop++) {
        *(tempArray + loop) = ntohs (*(tempArray + loop));
    }

    header->qr = bitmasks & 0x8000 ? 1 : 0;
    header->opcode = (bitmasks & 0x7800) >> 11;
    header->aa = bitmasks & 0x0400 ? 1 : 0;
    header->tc = bitmasks & 0x0200 ? 1 : 0;
    header->rd = bitmasks & 0x0100 ? 1 : 0;
    header->ra = bitmasks & 0x0080 ? 1 : 0;
    header->z = bitmasks & 0x0040 ? 1 : 0;
    /* don't think we care about these
    header->ad = bitmasks & 0x0020 ? 1 : 0;
    header->cd = bitmasks & 0x0010 ? 1 : 0; */
    header->rcode = bitmasks & 0x000f;
/*
    g_debug("header->qr %d", header->qr);
    g_debug("header->opcode %d", header->opcode);
    g_debug("header->aa %d", header->aa);
    g_debug("header->tc %d", header->tc);
    g_debug("header->rd %d", header->rd);
    g_debug("header->ra %d", header->ra);
    g_debug("header->z %d", header->z);
    g_debug("header->rcode %d", header->rcode);
*/
}


#endif
