/**
 * @internal
 *
 * @file outputDumper.c
 *
 * This is used to banner grab the packets that it sees.  It is
 * _extremely_ slow.  No attempt to make it fast & efficient has
 * been made.  Don't expect to use this current implementation
 * on a production system.  It is useful to process captures
 * with this file and get ASCII text banners out that can
 * be processed with other tools as needed.
 *
 * @author $Author: ecoff_svn $
 * @version $Revision: 18678 $
 * @date $Date: 2013-01-29 15:29:45 -0500 (Tue, 29 Jan 2013) $
 *
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2007-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Chris Inacio <inacio@cert.org>
 ** ------------------------------------------------------------------------
 ** GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
 ** Government Purpose License Rights (GPLR) pursuant to DFARS 252.225-7013
 ** ------------------------------------------------------------------------
 *
 */
#define _YAF_SOURCE_
#include <yaf/autoinc.h>
#include <yaf/yafcore.h>
#include <yaf/decode.h>

#define MAX_HEADER 400

/**
 * dumpplugin_LTX_ycProtocolDumperScan
 *
 * @param argc number of string arguments in argv
 * @param argv string arguments for this plugin (first two are library
 *             name and function name)
 * @param payload the packet payload
 * @param payloadSize size of the packet payload
 * @param flow a pointer to the flow state structure
 * @param val a pointer to biflow state (used for forward vs reverse)
 *
 *
 * @return always 0
 */
uint16_t
dumpplugin_LTX_ycProtocolDumperScan (
    int argc,
    char *argv[],
    uint8_t * payload,
    unsigned int payloadSize,
    yfFlow_t * flow,
    yfFlowVal_t * val)
{
    unsigned int        loop;
    unsigned int        packetMax =
      payloadSize < MAX_HEADER ? payloadSize : MAX_HEADER;
    FILE               *dumpFile = NULL;


    if (argc < 3) {
        return 0;
    }

    dumpFile = fopen (argv[2], "a");
    if (NULL == dumpFile) {
        return 0;
    }


    for (loop = 0; loop < packetMax; loop++) {
        fprintf (dumpFile, "%d ", *(payload + loop));
    }
    fprintf (dumpFile, "\n");

    fclose (dumpFile);
    return 0;
}
