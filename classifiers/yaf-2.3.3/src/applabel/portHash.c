/**
 *@internal
 *
 *@file portHash.c
 *
 * This creates a really simple hash table to store a mapping between
 * port numbers and rules.  The hash is really an implementation of
 * a sparse array.
 *
 * Also in the hash table are the DPI rules and index numbers to the
 * structures defined in dpacketplugin.c.  Try to avoid collisions by
 * not using well-known ports used in the applabel plug-in:
 * 80, 22, 25, 6346, 5050, 53, 21, 443, 427, 143, 194
 *
 * @author $Author: ecoff_svn $
 * @date $Date: 2013-01-29 15:29:45 -0500 (Tue, 29 Jan 2013) $
 * @version $Revision: 18678 $
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
#include "portHash.h"

#if YAF_ENABLE_APPLABEL

/** defining unit test makes this into a self compilable file and tries
    to do some (very minimal) testing of the hash functions */
#ifdef UNIT_TEST
typedef struct GError_st {
    int                 foo;
} GError;
typedef uint8_t     gboolean;

static int          primaryHash;
static int          secondaryHash;
static int          linearChaining;

#endif

static int linearChainingMax;

#include "payloadScanner.h"


/*
 * local types
 */
typedef struct portRuleHash_st {
    uint16_t            portNumber;
    uint16_t            ruleIndex;
} portRuleHash_t;


/*
 * file locals
 */
static portRuleHash_t portRuleHash[MAX_PAYLOAD_RULES];


/**
 * ycPortHashInitialize
 *
 * initializes the port hash to mark each entry as empty
 *
 *
 */
void
ycPortHashInitialize (
    )
{
    int                 loop;

    for (loop = 0; loop < MAX_PAYLOAD_RULES; loop++) {
        portRuleHash[loop].ruleIndex = MAX_PAYLOAD_RULES + 1;
    }
#   ifdef UNIT_TEST
    primaryHash = 0;
    secondaryHash = 0;
    linearChaining = 0;
#   endif
    linearChainingMax = 0;
}



/**
 * ycPortHashInsert
 *
 * this inserts a mapping between port numbers and rule processing into
 * a hash.  The hash is used as a sparse array mechanism, although it
 * does take into account getting less sparse somewhat.  The hash can
 * hold as many elements as there are rules.  This might be somewhat
 * less efficient than a direct array if it gets full enough.
 * (Always a problem with sparse representations when they become
 * un-sparse.)
 * It uses a primary hash, a secondary hash, and then linear chaining
 * for its insert mechanism.
 *
 * @param portNum the TCP/UDP port number for the protocol (we use
 *        the label given in the rules file)
 * @param ruleNum the entry number in the rule table, this is the
 *        order the rule was declared in
 *
 */
void
ycPortHashInsert (
    uint16_t portNum,
    uint16_t ruleNum)
{
    uint16_t            insertLoc = portNum % MAX_PAYLOAD_RULES;
    int linChain = 0;

    /* primary hash function insert, check for collision */
    if ((MAX_PAYLOAD_RULES + 1) == portRuleHash[insertLoc].ruleIndex) {
        portRuleHash[insertLoc].portNumber = portNum;
        portRuleHash[insertLoc].ruleIndex = ruleNum;
#       ifdef UNIT_TEST
        primaryHash++;
#       endif
        return;
    }

    /* secondary hash function, insert with collision check */
    insertLoc = ((MAX_PAYLOAD_RULES - portNum) ^ (portNum >> 8));
    insertLoc %= MAX_PAYLOAD_RULES;
    if ((MAX_PAYLOAD_RULES + 1) == portRuleHash[insertLoc].ruleIndex) {
        portRuleHash[insertLoc].portNumber = portNum;
        portRuleHash[insertLoc].ruleIndex = ruleNum;
#       ifdef UNIT_TEST
        secondaryHash++;
#       endif
        return;
    }

    /* linear chaining from secondary hash function */
    do {
        insertLoc = (insertLoc + 1) % MAX_PAYLOAD_RULES;
        if ((MAX_PAYLOAD_RULES + 1) == portRuleHash[insertLoc].ruleIndex) {
            portRuleHash[insertLoc].portNumber = portNum;
            portRuleHash[insertLoc].ruleIndex = ruleNum;
#           ifdef UNIT_TEST
            linearChaining++;
#           endif
            if (linChain > linearChainingMax) {
                linearChainingMax = linChain;
            }
            return;
        }
        linChain++;
    } while ((portNum ^ (portNum >> 8)) % MAX_PAYLOAD_RULES != insertLoc);

    /* hash table must be full */
    /*
     * currently the hash table being full is an error, but I want to add
     * "alias" commands into the rule file so that a single rule can
     * be hinted to operate on multiple ports, e.g. SSL/TLS for 993
     * IMAPS as well as 443 HTTPS
     *
     */
}


/**
 * ycPortHashSearch
 *
 * searches the port number to scan rule hash to find the appropriate
 * rule based on the port number, uses the same hashing mechanism as
 * ycPortHashInsert.
 *
 * @param portNum the TCP/UDP port number to search for a detection
 *        rule index on
 *
 * @return the rule index to the scan rule table to use to try to
 *         payload detect if a match is found, otherwise it
 *         returns MAX_PAYLOAD_RULES+1 if there is no match
 */
uint16_t
ycPortHashSearch (
    uint16_t portNum)
{
    uint16_t            searchLoc = portNum % MAX_PAYLOAD_RULES;
    int                 linChain = 0;

    /* primary hash search */
    if (portRuleHash[searchLoc].portNumber == portNum) {
        return portRuleHash[searchLoc].ruleIndex;
    }

    /* secondary hash function and search */
    searchLoc = ((MAX_PAYLOAD_RULES - portNum) ^ (portNum >> 8));
    searchLoc %= MAX_PAYLOAD_RULES;
    if (portRuleHash[searchLoc].portNumber == portNum) {
        return portRuleHash[searchLoc].ruleIndex;
    }

    /* drop down to linear chaining from secondary hash function */
    do {
        searchLoc = (searchLoc + 1) % MAX_PAYLOAD_RULES;
        if (portRuleHash[searchLoc].portNumber == portNum) {
            return portRuleHash[searchLoc].ruleIndex;
        }
        linChain++;
    } while (((portNum ^ (portNum >> 8)) % MAX_PAYLOAD_RULES != searchLoc)
             && (linChain <= linearChainingMax));

    /* no match found */
    return (MAX_PAYLOAD_RULES + 1);
}



#ifdef UNIT_TEST
/**
 * main
 *
 * this is only used when unit testing the hash.  For production everything
 * within the #ifdef for UNIT_TEST should be ignored
 *
 */
int
main (
    int argc,
    char *argv[])
{
    ycPortHashInitialize ();

    // first lets do a "practical" example to see how the hash functions
    // operate
    printf ("inserting: {80,0}, {25,1}, {53,2}, {21,3}, {143,4}, {443,5}\n");
    ycPortHashInsert (80, 0);
    ycPortHashInsert (25, 1);
    ycPortHashInsert (53, 2);
    ycPortHashInsert (21, 3);
    ycPortHashInsert (143, 4);
    ycPortHashInsert (443, 5);

    printf ("searching:\n");
    printf ("21, %d\n", ycPortHashSearch (21));
    printf ("25, %d\n", ycPortHashSearch (25));
    printf ("53, %d\n", ycPortHashSearch (53));
    printf ("143, %d\n", ycPortHashSearch (143));
    printf ("80, %d\n", ycPortHashSearch (80));
    printf ("443, %d\n", ycPortHashSearch (443));

    printf ("hashing functions used: primary: %d secondary: %d linear: %d\n",
            primaryHash, secondaryHash, linearChaining);


    printf ("inserting conflicts:\n");
    ycPortHashInsert (80 + MAX_PAYLOAD_RULES, 6);
    ycPortHashInsert (25 + MAX_PAYLOAD_RULES, 7);
    ycPortHashInsert (53 + MAX_PAYLOAD_RULES, 8);

    printf ("searching:\n");
    printf ("%d, %d\n", (80 + MAX_PAYLOAD_RULES),
            ycPortHashSearch (80 + MAX_PAYLOAD_RULES));
    printf ("%d, %d\n", (25 + MAX_PAYLOAD_RULES),
            ycPortHashSearch (25 + MAX_PAYLOAD_RULES));
    printf ("%d, %d\n", (53 + MAX_PAYLOAD_RULES),
            ycPortHashSearch (53 + MAX_PAYLOAD_RULES));

    printf ("hashing functions used: primary: %d secondary: %d linear: %d\n",
            primaryHash, secondaryHash, linearChaining);

    printf ("testing wrap around + linear chaining\n");
    ycPortHashInsert ((MAX_PAYLOAD_RULES - 3) + (0 * MAX_PAYLOAD_RULES), 9);
    ycPortHashInsert ((MAX_PAYLOAD_RULES - 3) + (1 * MAX_PAYLOAD_RULES), 10);
    ycPortHashInsert ((MAX_PAYLOAD_RULES - 3) + (2 * MAX_PAYLOAD_RULES), 11);
    ycPortHashInsert ((MAX_PAYLOAD_RULES - 3) + (3 * MAX_PAYLOAD_RULES), 12);
    ycPortHashInsert ((MAX_PAYLOAD_RULES - 3) + (4 * MAX_PAYLOAD_RULES), 13);
    ycPortHashInsert ((MAX_PAYLOAD_RULES - 3) + (5 * MAX_PAYLOAD_RULES), 14);

    printf ("searching:\n");
    printf ("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (0 * MAX_PAYLOAD_RULES),
            ycPortHashSearch ((MAX_PAYLOAD_RULES - 3) +
                              (0 * MAX_PAYLOAD_RULES)));
    printf ("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (1 * MAX_PAYLOAD_RULES),
            ycPortHashSearch ((MAX_PAYLOAD_RULES - 3) +
                              (1 * MAX_PAYLOAD_RULES)));
    printf ("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (2 * MAX_PAYLOAD_RULES),
            ycPortHashSearch ((MAX_PAYLOAD_RULES - 3) +
                              (2 * MAX_PAYLOAD_RULES)));
    printf ("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (3 * MAX_PAYLOAD_RULES),
            ycPortHashSearch ((MAX_PAYLOAD_RULES - 3) +
                              (3 * MAX_PAYLOAD_RULES)));
    printf ("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (4 * MAX_PAYLOAD_RULES),
            ycPortHashSearch ((MAX_PAYLOAD_RULES - 3) +
                              (4 * MAX_PAYLOAD_RULES)));
    printf ("%d, %d\n", (MAX_PAYLOAD_RULES - 3) + (5 * MAX_PAYLOAD_RULES),
            ycPortHashSearch ((MAX_PAYLOAD_RULES - 3) +
                              (5 * MAX_PAYLOAD_RULES)));

    printf ("hashing functions used: primary: %d secondary: %d linear: %d\n",
            primaryHash, secondaryHash, linearChaining);

    return 0;
}

#endif /* UNIT_TEST */


#endif
