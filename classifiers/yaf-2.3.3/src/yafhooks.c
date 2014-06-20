/*
 ** @internal
 **
 ** yafhooks.c
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

#define _YAF_SOURCE_
#include <yaf/yafhooks.h>
#include <ltdl.h>
#if YAF_ENABLE_HOOKS
/* define a quick variable argument number macro to simply sending an error back to the yaf "core" */
#define gerr(e, ...) {if (NULL == e) { *e = g_error_new(__VA_ARGS__); } else { g_set_error(e, __VA_ARGS__); }}

#define YAF_SEARCH_LIB "/usr/local/lib/yaf"

/** this flag contains the number of plugins that have been hooked in */
unsigned int yaf_hooked = 0;

static const char *pluginFunctionNames[] = {
    "ypGetMetaData",
    "ypHookPacket",
    "ypFlowPacket",
    "ypFlowClose",
    "ypFlowAlloc",
    "ypFlowFree",
    "ypFlowWrite",
    "ypGetInfoModel",
    "ypGetTemplate",
    "ypSetPluginOpt",
    "ypSetPluginConf",
#if YAF_ENABLE_APPLABEL
    "ypScanPayload",
#endif
    "ypValidateFlowTab",
    "ypGetTemplateCount",
    "ypFreeLists"
};

typedef const struct yfHookMetaData* (*yfHookGetMetaData_fn)(void);
typedef gboolean (*yfHookPacket_fn)(yfFlowKey_t *key, const uint8_t *pkt,
                    size_t caplen, uint16_t iplen,
                    yfTCPInfo_t *tcpinfo, yfL2Info_t *l2info);
typedef void (*yfHookFlowPacket_fn)(void * yfHookConext, yfFlow_t *flow,
                    yfFlowVal_t *val, const uint8_t *pkt,
                    size_t caplen, uint16_t iplen,
                    yfTCPInfo_t *tcpinfo, yfL2Info_t *l2info);
typedef gboolean (*yfHookFlowClose_fn)(void * yfHookConext, yfFlow_t *flow);
typedef void (*yfHookFlowAlloc_fn)(void ** yfHookConext, yfFlow_t *flow);
typedef void (*yfHookFlowFree_fn)(void * yfHookConext, yfFlow_t *flow);
typedef gboolean (*yfWriteFlowHook_fn)(void * yfHookConext,
                                       fbSubTemplateMultiList_t *rec,
                                       fbSubTemplateMultiListEntry_t *stml,
                                       yfFlow_t *flow, GError **err);
typedef fbInfoElement_t * (*yfHookGetInfoModel_fn)(void);
typedef gboolean (*yfHookGetTemplate_fn)(fbSession_t *session);
typedef void (*yfHookSetPluginOpt_fn)(const char * pluginOpt);
typedef void (*yfHookSetPluginConf_fn)(const char * pluginConf);
#if YAF_ENABLE_APPLABEL
typedef void (*yfHookScanPayload_fn)(void *yfHookConext, yfFlow_t *flow,
                     const uint8_t *pkt, size_t caplen,
                     pcre *expression, uint16_t offset,
                     uint16_t elementID, uint16_t applabel);
#endif
typedef gboolean (*yfHookValidateFlowTab_fn)(uint32_t max_payload,
                                             gboolean uniflow,
                                             gboolean silkmode,
                                             gboolean applabelmode,
                                             gboolean entropymode,
                                             gboolean fingerprintmode,
                                             gboolean fpExportMode,
                                             gboolean udp_max_payload,
                                             uint16_t udp_uniflow_port,
                                             GError **err);
typedef uint8_t (*yfHookGetTemplateCount_fn)(void *yfHookConext, yfFlow_t *flow);
typedef void (*yfHookFreeLists_fn)(void * yfHookConext, yfFlow_t *flow);

typedef struct yfHooksFuncs_st {
    yfHookGetMetaData_fn    getMetaData;
    yfHookPacket_fn         hookPacket;
    yfHookFlowPacket_fn     flowPacket;
    yfHookFlowClose_fn      flowClose;
    yfHookFlowAlloc_fn      flowAlloc;
    yfHookFlowFree_fn       flowFree;
    yfWriteFlowHook_fn      flowWrite;
    yfHookGetInfoModel_fn   modelGet;
    yfHookGetTemplate_fn    templateGet;
    yfHookSetPluginOpt_fn   setPluginOpt;
    yfHookSetPluginConf_fn  setPluginConf;
#if YAF_ENABLE_APPLABEL
    yfHookScanPayload_fn    scanPayload;
#endif
    yfHookValidateFlowTab_fn validateFlowTab;
    yfHookGetTemplateCount_fn getTemplateCount;
    yfHookFreeLists_fn       freeLists;
} yfHooksFuncs_t;

typedef struct yfHookPlugin_st {
    lt_dlhandle         pluginHandle;
    union {
        lt_ptr              genPtr[sizeof (pluginFunctionNames) /
                                   sizeof (char *)];
        yfHooksFuncs_t          funcPtrs;
    } ufptr;
    struct yfHookPlugin_st *next;
} yfHookPlugin_t;


/** pointer to a _simple_ linked list of plugins registered
    for this program run
  */
static yfHookPlugin_t *headPlugin = NULL;

/** keeps a running sum of the total amount of data exported
    by the plugins, so that there isn't an overrun in the fixed
    size output buffer
  */
static uint32_t totalPluginExportData = 0;

/** need to remember the export data size of each hooked plugin, and
    advance the data array pointer an appropriate amount for each
    write call
  */
static uint32_t pluginExportSize[YAF_MAX_HOOKS];

/**
 * yfHookPacket
 *
 *
 *
 */
gboolean
yfHookPacket (
    yfFlowKey_t * key,
    const uint8_t * pkt,
    size_t caplen,
    uint16_t iplen,
    yfTCPInfo_t * tcpinfo,
    yfL2Info_t * l2info)
{
    yfHookPlugin_t      *pluginIndex;
    unsigned int         loop;

    pluginIndex = headPlugin;

    for (loop = 0; loop < yaf_hooked; loop++) {
        if (NULL == pluginIndex) {
            break;
        }
        if (FALSE == (pluginIndex->ufptr.funcPtrs.hookPacket) (key, pkt, caplen,
                                                               iplen, tcpinfo,
                                                               l2info))
        {
            return FALSE;
        }
        pluginIndex = pluginIndex->next;
    }

    return TRUE;
}

/**
 * yfHookFlowPacket
 *
 *
 *
 */
void
yfHookFlowPacket (
    yfFlow_t * flow,
    yfFlowVal_t *val,
    const uint8_t *pkt,
    size_t caplen,
    uint16_t iplen,
    yfTCPInfo_t * tcpinfo,
    yfL2Info_t * l2info)
{
    yfHookPlugin_t      *pluginIndex;
    unsigned int        loop = 0;

    pluginIndex = headPlugin;

    for (loop=0; loop < yaf_hooked; loop++) {
        if (NULL == pluginIndex) {
            break;
        }
        (pluginIndex->ufptr.funcPtrs.flowPacket) ((flow->hfctx)[loop], flow,
                          val, pkt, caplen, iplen,
                          tcpinfo, l2info);
        pluginIndex = pluginIndex->next;
}
    return;
}

/**
 * yfHookValidateFlowTab
 *
 * Check to make sure plugin can operate with flowtable options
 *
 */
void
yfHookValidateFlowTab(
    uint32_t        max_payload,
    gboolean        uniflow,
    gboolean        silkmode,
    gboolean        applabelmode,
    gboolean        entropymode,
    gboolean        fingerprintmode,
    gboolean        fpExportMode,
    gboolean        udp_max_payload,
    uint16_t        udp_uniflow_port)
{

    yfHookPlugin_t    *pluginIndex;
    yfHookPlugin_t    *currentIndex;
    yfHookPlugin_t    *lastIndex;
    int               loop = 0;
    GError            *err = NULL;
    int               hooked = yaf_hooked;

    pluginIndex = headPlugin;
    lastIndex = headPlugin;

    for (loop = 0; loop < hooked; loop++) {
       if (NULL == pluginIndex) {
           break;
       }
       if (FALSE == pluginIndex->ufptr.funcPtrs.validateFlowTab(max_payload,
                                                        uniflow,
                                                        silkmode,
                                                        applabelmode,
                                                        entropymode,
                                                        fingerprintmode,
                                                        fpExportMode,
                                                        udp_max_payload,
                                                        udp_uniflow_port,
                                                        &err))
       {
           g_warning("Plugin: %s", err->message);
           currentIndex = pluginIndex;
           pluginIndex = pluginIndex->next;
           if (currentIndex == headPlugin) {
               headPlugin = pluginIndex;
           } else {
               lastIndex->next = pluginIndex->next;
           }
           free(currentIndex);
           yaf_hooked--;
           g_clear_error(&err);
       } else {
           pluginIndex = pluginIndex->next;
       }

    }
    return;
}


/**
 *
 *
 *
 *
 */
gboolean
yfHookFlowClose (
    yfFlow_t * flow)
{
    yfHookPlugin_t      *pluginIndex;
    unsigned int        loop = 0;

    pluginIndex = headPlugin;

    for (loop=0; loop < yaf_hooked; loop++) {
        if (NULL == pluginIndex) {
            break;
        }
        if (FALSE == pluginIndex->ufptr.funcPtrs.flowClose((flow->hfctx)[loop],
                                                           flow))
        {
            return FALSE;
        }
        pluginIndex = pluginIndex->next;
    }

    return TRUE;
}

/**
 * yfHookFlowAlloc
 *
 * this is called to give the plugins a chance to allocate flow state information
 * for each flow captured by yaf
 *
 * @param flow the pointer to the flow context state structure, but more importantly
 *        in this case, it contains the array of pointers (hfctx) which hold the
 *        plugin context state
 *
 */
void
yfHookFlowAlloc (
    yfFlow_t * flow)
{
    yfHookPlugin_t      *pluginIndex;
    unsigned int        loop = 0;

    pluginIndex = headPlugin;

    for (loop=0; loop < yaf_hooked; loop++) {
        if (NULL == pluginIndex) {
            break;
        }
        (pluginIndex->ufptr.funcPtrs.flowAlloc) (&((flow->hfctx)[loop]), flow);
        pluginIndex = pluginIndex->next;
    }
    return;
}

/**
 * yfHookFlowFree
 *
 * this frees all memory associated with the flow state in all of the attached
 * plugins
 *
 * @param flow a pointer to the flow context structure
 *
 */
void
yfHookFlowFree (
    yfFlow_t * flow)
{
    yfHookPlugin_t      *pluginIndex;
    unsigned int        loop = 0;

    pluginIndex = headPlugin;

    for (loop=0; loop < yaf_hooked; loop++) {
        if (NULL == pluginIndex) {
            break;
        }
        (pluginIndex->ufptr.funcPtrs.flowFree) ((flow->hfctx)[loop], flow);
        pluginIndex = pluginIndex->next;
    }

    return;
}

/**
 * yfHookGetInfoModel
 *
 * returns the IPFIX info model aggregated for all plugins
 *
 * @bug it permanently caches an aggregate of all the info model
 *      information from each plugin; some might call this a leak
 *
 * @return pointer to an array of fbInfoElement_t that contains
 *         the sum of the IPFIX IE's from all active plugins
 *
 */
fbInfoElement_t    *
yfHookGetInfoModel (
  )
{
    static unsigned int cached = 0;
    yfHookPlugin_t      *pluginIndex;
    static fbInfoElement_t     *cachedIM = NULL;
    fbInfoElement_t     *tempIM = NULL;
    unsigned int        totalIMSize = 0;
    unsigned int        partialIMSize = 0;
    unsigned int        imIndex;
    unsigned int        loop;

    if (0 == yaf_hooked) {
        return NULL;
    }

    if (yaf_hooked == cached && 0 != cached) {
        return cachedIM;
    } else if (0 != cached ) {
        g_free(cachedIM);
        cachedIM = NULL;
    }


    /* iterate through the plugins and on the first pass simply count the
       number of info model enteries each one has
     */
    pluginIndex = headPlugin;
    for (loop=0; loop < yaf_hooked; loop++) {
        if (NULL == pluginIndex) {
            g_error("internal error iterating plugins, cannot continue");
            break;
        }
        tempIM = (pluginIndex->ufptr.funcPtrs.modelGet) ();
        if (NULL != tempIM) {
            partialIMSize = 0;
            for (partialIMSize = 0; (tempIM+partialIMSize)->ref.name != NULL ; partialIMSize++) {
            }
            totalIMSize += partialIMSize;
        }
        pluginIndex = pluginIndex->next;
    }

    /* allocate an array of info element enteries to hold the sum total of all
       IE's from all the plugins.  Add 1 to add a NULL entry at the end
    */
    cachedIM = g_new(fbInfoElement_t, totalIMSize+1);

    /* now iterate through each plugin and copy each info model entry from
       the returned array into the local cache copy that was just allocated
    */
    pluginIndex = headPlugin;
    imIndex = 0;
    for (loop=0; loop < yaf_hooked; loop++) {
        if (NULL == pluginIndex) {
            g_error("internal error iterating plugins, cannot continue");
            break;
        }
        tempIM = (pluginIndex->ufptr.funcPtrs.modelGet) ();
        if (NULL != tempIM) {
            for (partialIMSize = 0; (tempIM+partialIMSize)->ref.name != NULL ; partialIMSize++) {
                memcpy(cachedIM+imIndex, tempIM+partialIMSize,
                       sizeof(fbInfoElement_t));
                imIndex++;
            }
        }
        pluginIndex = pluginIndex->next;
    }


    /* copy the NULL element field into the end of the combined $ array, this
       works because at the end of the previous for loop, partialIMSize should
       always be pointing to a NULL field, based on the for loop test */
    memcpy(cachedIM+totalIMSize, tempIM+partialIMSize,
           sizeof(fbInfoElement_t));


    cached = yaf_hooked;
    return cachedIM;
}

/**
 * yfHookGetTemplate
 *
 * gets the IPFIX info model template for the export data from _all_ the
 * plugins and turns it into a single template to return.  It caches the
 * results so that future queries are a lot faster.  It can invalidate the
 * cached result if the number of plugins registered changes.
 *
 * @return pointer to an array of fbInfoElementSpec_t structures that describe
 * the info model template
 *
 */
gboolean
yfHookGetTemplate (
    fbSession_t *session)
{
    yfHookPlugin_t      *pluginIndex = NULL;
    int                 loop;
    int                 hooked = yaf_hooked;

    /* first check if we've cached any results yet, if not, do the work
       then check to see if this result was cached before (good chance it was,
       but make sure it is up to date)
       if it's not up to date, through it away and recompute the result
     */

    if (0 == yaf_hooked) {
        return TRUE;
    }

    pluginIndex = headPlugin;

    for (loop = 0; loop < hooked; loop++) {
        if (NULL == pluginIndex) {
            g_error("internal error iterating plugins, cannot continue");
            return FALSE;
        }
        if (!(pluginIndex->ufptr.funcPtrs.templateGet) (session)) {
            g_debug("Error Getting Template for Hooks: "
                    "Plugin can not be used");
            yaf_hooked--;
        }
        pluginIndex = pluginIndex->next;
    }

    return TRUE;
}

/**
 *
 *
 *
 *
 */
gboolean
yfWriteFlowHook (
    fbSubTemplateMultiList_t *rec,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t * flow,
    GError ** err)
{
    yfHookPlugin_t      *pluginIndex;
    unsigned int        loop;

    pluginIndex = headPlugin;

    for (loop = 0; loop < yaf_hooked; loop++) {
        if (NULL == pluginIndex) {
            break;
        }

        if (FALSE == pluginIndex->ufptr.funcPtrs.flowWrite((flow->hfctx)[loop],
                                rec, stml, flow, err))
        {
            return FALSE;
        }
        pluginIndex = pluginIndex->next;
    }

    return TRUE;
}



/**
 *yfHookAddNewHook
 *
 * adds another hook (plugin) into yaf
 *
 * @param hookName the file name of the plugin to load
 * @param hookOpts a string of command line options for the plugin to process
 * @param hookConf the filename of the configuration file to load
 * @param err the error value that gets set if this call didn't work
 *
 * @return TRUE if plugin loaded fine, other FALSE
 *
 */
gboolean
yfHookAddNewHook (
    const char *hookName,
    const char *hookOpts,
    const char *hookConf,
    GError ** err)
{
    int             rc;
    lt_dlhandle     libHandle;
    lt_ptr          genericLtPtr;
    unsigned int    loop;
    yfHookPlugin_t  *newPlugin = NULL;
    yfHookPlugin_t  *pluginIndex;
    const struct yfHookMetaData *md;

    /* check to make sure we aren't exceeding the number of allowed hooks */
    if (YAF_MAX_HOOKS == yaf_hooked)
    {
        gerr (err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                     "Maximum number of plugins exceeded, limit is %d",
                     YAF_MAX_HOOKS);
        return FALSE;
    }

    /*  initialize the dynamic loader library before we ty to use it, it is
        harmless to call this one than once */
    if ((rc = lt_dlinit ())) {
        gerr (err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                     "Couldn't initialize LTDL library loader: %s",
                     lt_dlerror ());
        return FALSE;
    }


    /* load the plugin by name, the library will try platform appropriate
       extensions */
    libHandle = lt_dlopenext (hookName);
    if (NULL == libHandle) {
        gerr (err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                     "failed to load plugin \"%s\" with reason: %s", hookName,
                     lt_dlerror ());
        return FALSE;
    }


    /* build a new handle for the plugin and initialize it */
    newPlugin = (yfHookPlugin_t *) malloc (sizeof (yfHookPlugin_t));
    if (NULL == newPlugin) {
        lt_dlclose (libHandle);
        gerr (err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
                     "couldn't allocate memory to load plugin\n");
        return FALSE;
    }
    newPlugin->pluginHandle = libHandle;
    newPlugin->next = NULL;


     /* load in all the function pointers from the library, search by name */
    for (loop = 0; loop < sizeof (pluginFunctionNames) / sizeof (char *); loop++) {
        genericLtPtr = lt_dlsym (libHandle, pluginFunctionNames[loop]);
        if (NULL == genericLtPtr) {
            break;
        }
        newPlugin->ufptr.genPtr[loop] = genericLtPtr;
    }

    /* make sure all the functions were loaded correctly */
    if (loop < sizeof (pluginFunctionNames) / sizeof (char *)) {
        gerr (err, YAF_ERROR_DOMAIN, YAF_ERROR_ARGUMENT,
                     "missing function \"%s\" in %s plugin",
              pluginFunctionNames[loop], hookName);
        return FALSE;
    }

     /* insert this plugin into an empty plugin list */
    if (NULL == headPlugin) {
            headPlugin = newPlugin;
    } else {
          /* if there is alredy a plugin installed, add this plugin to the list */
         pluginIndex = headPlugin;
         while (pluginIndex->next) {
             pluginIndex = pluginIndex->next;
         }

         pluginIndex->next = newPlugin;
    }


    /** get the metadata information from the plugin, and make sure that
        yaf can still operate with it installed */
    md = newPlugin->ufptr.funcPtrs.getMetaData();
    if (YAF_HOOK_INTERFACE_VERSION < md->version)
    {
        gerr(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
            "incompatible plugin version, max supported is %d, plugin is %d",
            YAF_HOOK_INTERFACE_VERSION, md->version);
        return FALSE;
    } else if (YAF_HOOK_INTERFACE_VERSION != md->version) {
        g_warning("Incompatible plugin version.");
        g_warning("YAF uses version %d, Plugin is version: %d",
                  YAF_HOOK_INTERFACE_VERSION, md->version);
        g_warning("Make sure you set LTDL_LIBRARY_PATH to correct location.");
        g_warning("yaf continuing... some functionality may not be available.");
    }

    if (YAF_HOOKS_MAX_EXPORT < totalPluginExportData+md->exportDataSize )
    {
        gerr(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
         "maximum plugin export data limit exceeded");
        return FALSE;
    }
#ifndef YAF_ENABLE_APPLABEL
    if (md->requireAppLabel == 1) {
        gerr(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
         "this plugin requires --enable-applabel");
        return FALSE;
    }
#endif
    /* record the export size for this plugin, and update the running total */
    pluginExportSize[yaf_hooked] = md->exportDataSize;
    totalPluginExportData += md->exportDataSize;

    /* pass hookConf to plugin */
    newPlugin->ufptr.funcPtrs.setPluginConf(hookConf);

    /* pass hookOpts to plugin */
    newPlugin->ufptr.funcPtrs.setPluginOpt(hookOpts);

    /** mark that another plugin has been hooked */
    yaf_hooked++;

    return TRUE;
}

#if YAF_ENABLE_APPLABEL
/**
 * yfHookScanPayload
 *
 *
 */
void
yfHookScanPayload (
    yfFlow_t *flow,
    const uint8_t *pkt,
    size_t caplen,
    pcre *expression,
    uint16_t offset,
    uint16_t elementID,
    uint16_t applabel)

{
    yfHookPlugin_t     *pluginIndex;
    unsigned int       loop = 0;

    pluginIndex = headPlugin;

    for (loop = 0; loop < yaf_hooked; loop++) {
    if (NULL == pluginIndex) {
        break;
    }
    (pluginIndex->ufptr.funcPtrs.scanPayload)((flow->hfctx)[loop], flow,
                          pkt, caplen, expression,
                          offset, elementID, applabel);

    pluginIndex = pluginIndex->next;
    }
    return;
}

#endif

/**
 *yfHookGetTemplateCount
 *
 *
 */
uint8_t
yfHookGetTemplateCount(
    yfFlow_t *flow)
{

    uint8_t count = 0;
    unsigned int loop;
    yfHookPlugin_t   *pluginIndex;

    pluginIndex = headPlugin;

    for (loop = 0; loop < yaf_hooked; loop++) {
        if (NULL == pluginIndex) {
            break;
        }
        count += ((pluginIndex->ufptr.funcPtrs.getTemplateCount)((flow->hfctx)[loop], flow));
        pluginIndex = pluginIndex->next;
    }
    return count;
}

/**
 * yfHookFreeLists
 *
 *
 */
void
yfHookFreeLists(
    yfFlow_t *flow)
{
    unsigned int loop;
    yfHookPlugin_t *pluginIndex;

    pluginIndex = headPlugin;

    for (loop = 0; loop < yaf_hooked; loop++) {
        if (NULL == pluginIndex) {
            break;
        }
        (pluginIndex->ufptr.funcPtrs.freeLists)((flow->hfctx)[loop], flow);
        pluginIndex = pluginIndex->next;
    }
}

#endif
