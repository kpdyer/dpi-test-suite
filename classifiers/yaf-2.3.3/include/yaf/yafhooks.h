/*
 ** yafhooks.h
 ** YAF Active Flow Table Plugin Interface
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2007-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell
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
 */

/**
 * @file
 *
 * Processing hook interface for YAF.
 *
 * VERSION 3 - REQUIRES FIXBUF 1.0
 *
 * The plugin must implement all of the following functions:
 *
 * ypGetMetaData - returns the version, max export bytes, applabel enabled
 *
 * ypHookPacket - called by yfFlowPBuf()
 *
 * ypFlowPacket - called by yfFlowPBuf() and yfAppLabelFlow()
 * when called by yfAppLabelFlow - the last 3 parameters are 0
 *
 * ypFlowClose - called by yfFlowClose()
 *
 * ypFlowAlloc - called by yfFlowGetNode()
 *
 * ypFlowFree - called by yfFlowFree()
 *
 * ypGetInfoModel - called by yfInfoModel() - this should not be used for v.3
 *
 * ypGetTemplate - called by yfInitExporterSession()
 *
 * ypSetPluginOpt - called by yfHookAddNewHook()
 *
 * ypSetPluginConf - called by yfHookAddNewHook()
 *
 * ypScanPayload - if Application labeling is enabled, called by app plugins
 *
 * ypValidateFlowTab - called by yfFlowTabAlloc()
 *
 * ypGetTemplateCount - called by yfWriteFlow()
 *
 * ypFreeLists - called by yfWriteFlow()
 *
 *
 */

/*

Design notes:

1. For now, it is okay for the yfhook facility to only support a single hook.

5. Each hook needs to know when a flow is flushed, so that it can make the
per-flow export fields available.

Changes in Version 4:

Added a function to pass a config file to the plugin from the command line.

Changes in Version 3:

Hooks export entire templates that will be added to Yaf's subTemplateMultiList.
yfWriteFlow in yafcore.c will call ypGetTemplateCount (a function as of v. 3),
which will return the number of templates Yaf should alloc in the STML.  When
yfHookWriteFlow is called the STML entry can be added.  The hook should not
add NULL entries, if no template is to be added, ypGetTemplateCount should return
0.  If the STML entry contains list fields (BL's, STL's, STML's), it must free
these in the call to ypFreeLists.  This means that the hook must maintain
access to the record so that it can free it.
ypFreeList does NOT free Yaf's STML, yaf will free this after all the hook's
lists have been freed.

As of Version 3, ypGetTemplate will call fbTemplateAppendSpecArray and
fbSessionAddTemplate.  It does not need to internal templates, only external.

ypGetInfoModel should no longer be used.  ypGetTemplate should allocate the
info model and add the elements to the info model & the template.

Versions 2 or Below:

Each hook needs to be able to hand YAF an export template for its fields.
These fields will appear in every exported record; a facility for NULLs MUST
be provided by the hook's representation.

*/

#ifndef _YAF_HOOKS_H_
#define _YAF_HOOKS_H_

#include <yaf/autoinc.h>
#include <yaf/decode.h>
#include <yaf/yafcore.h>
#include <yaf/yaftab.h>
#if YAF_ENABLE_APPLABEL
#include <pcre.h>
#endif

/** HOOKS Plugin Version */
#define YAF_HOOK_INTERFACE_VERSION 5

/** Exported from the plugin to tell YAF about its export data & interface version */
struct yfHookMetaData {
    /** version of plugin interface */
    uint8_t version;
    /** size of data plugin will export */
    uint32_t exportDataSize;
    /** turn on application labeling related functions */
    uint8_t requireAppLabel;
};


/**
 * Function called to do processing on each packet as it comes in
 *
 * @param key pointer to flowkey
 * @param pkt pointer to pkt data
 * @param caplen size of pkt data
 * @param iplen
 * @param tcpinfo
 * @param l2info
 * @return TRUE if pkt processing should continue, FALSE if not
 *
 */
gboolean            yfHookPacket (
    yfFlowKey_t * key,
    const uint8_t * pkt,
    size_t caplen,
    uint16_t iplen,
    yfTCPInfo_t * tcpinfo,
    yfL2Info_t * l2info);

/**
 * Similar to yfHookPacket but also given yfFlowVal_t struct for
 * processing per flow direction
 *
 * @param flow pointer to yfFlow_t
 * @param val pointer to yfFlowVal_t struct
 * @param pkt pointer to pkt data
 * @param caplen size of pkt data
 * @param iplen
 * @param tcpinfo
 * @param l2info
 */
void                yfHookFlowPacket (
    yfFlow_t * flow,
    yfFlowVal_t * val,
    const uint8_t *pkt,
    size_t caplen,
    uint16_t iplen,
    yfTCPInfo_t * tcpinfo,
    yfL2Info_t * l2info);

/**
 * Validation function to make sure the plugin can and should operate
 * based on the flowtable options
 *
 * @param    max_payload value
 * @param    uniflow
 * @param    silkmode
 * @param    applabelmode
 * @param    entropymode
 * @param    fingerprintmode p0f finger printing mode
 * @param    fpExportMode handshake header export mode
 * @param    udp_max_payload   concatenate udp payloads similar to TCP
 * @param    udp_uniflow_port  export all udp packets if have this src or dst port
 */
void                yfHookValidateFlowTab (
    uint32_t        max_payload,
    gboolean        uniflow,
    gboolean        silkmode,
    gboolean        applabelmode,
    gboolean        entropymode,
    gboolean        fingerprintmode,
    gboolean        fpExportMode,
    gboolean        udp_max_payload,
    uint16_t        udp_uniflow_port);

/**
 * Called upon flow close to do any necessary
 * plugin processing upon flow close
 *
 * @param flow
 * @return TRUE or FALSE upon error
 */
gboolean            yfHookFlowClose (
    yfFlow_t * flow);

/**
 * Allow plugins to allocate flow state information for
 * each flow captured by yaf at the time of flow creation.
 *
 * @param flow the pointer to the flow context state structure, but
 * more importantly contains the array of pointers (hfctx) which
 * hold the plugin context state
 *
 */
void                yfHookFlowAlloc (
    yfFlow_t * flow);

/**
 * Frees all memory associated with the flow state in all of the
 * attached plugins
 *
 * @param  flow - a pointer to the flow context structure
 *
 */
void                yfHookFlowFree (
    yfFlow_t * flow);

/**
 * Returns the IPFIX info model aggregated for all plugins
 *
 * @return pointer to an array of fbInfoElement_t that contains
 * the sum of the IPFIX IE's from all active plugins
 */
fbInfoElement_t    *yfHookGetInfoModel (
    void);

/**
 *  Gets the IPFIX info model template for the export data from _all_
 *  the plugins and turns it into a single template to return.  It caches
 *  the results so that future queries are a lot faster.  It can validate
 *  the cached result if the numer of plugins registered changes.
 *
 *  @param session pointer to an array of fbInfoElementSpec_t structures
 *         that describes the info model template
 */
gboolean yfHookGetTemplate (
    fbSession_t *session);

/**
 * called by yfWriteFlow to add the data from all registered plugins
 * to the outgoing IPFIX record
 *
 * @param   rec outgoing subTemplateMultiList
 * @param   stml Current entry of subTemplateMultiList
 * @param   flow pointer to the flow context structure
 * @param   err Error
 */
gboolean            yfWriteFlowHook (
    fbSubTemplateMultiList_t *rec,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t * flow,
    GError ** err);

/**
 * Adds another hook (plugin) into yaf
 *
 * @param hookName the file name of the plugin to load
 * @param hookOpts a string of command line options for the plugin to process
 * @param hookConf the config file for the plugin
 * @param err the error value that gets set if this call didn't work
 *
 * @return TRUE if plugin loaded fine, other FALSE
 *
 */
gboolean yfHookAddNewHook(
    const char *hookName,
    const char *hookOpts,
    const char *hookConf,
    GError ** err);

#if YAF_ENABLE_APPLABEL
/**
 * Specifically if application labeling is enabled for deep packet
 * inspection plugin.
 *
 * @param flow
 * @param pkt pointer to payload
 * @param caplen payloadSize
 * @param expression PCRE expression to evaluate against payload
 * @param offset in payload to begin
 * @param elementID label for regex
 * @param applabel
 */
void yfHookScanPayload (
    yfFlow_t *flow,
    const uint8_t *pkt,
    size_t caplen,
    pcre *expression,
    uint16_t offset,
    uint16_t elementID,
    uint16_t applabel);

#endif

/**
 * Returns the amount of templates to add to the SubtemplateMultiList
 * from all plugins hooked.
 *
 * @param flow
 * @return number of templates to add to SubTemplateMultiList in yaf
 */
uint8_t yfHookGetTemplateCount(
    yfFlow_t *flow);

/**
 * Sends control back to the plugin to free any BasicLists, SubTemplateLists,
 * or SubTemplateMultiLists that may have been used in it's added templates.
 *
 * @param flow
 */
void yfHookFreeLists(
    yfFlow_t *flow);

#endif
