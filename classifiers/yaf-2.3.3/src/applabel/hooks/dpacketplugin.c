/**
 * @internal
 *
 * @file dpacketplugin.c
 *
 * Provides a plugin to inspect payloads and export the data
 * in ipfix template format.  See yafdpi(1)
 *
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Emily Sarneso
 ** ------------------------------------------------------------------------
 *
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
 *
 *
 */

#define _YAF_SOURCE_

#include "dpacketplugin.h"

#if YAF_ENABLE_APPLABEL

#if YAF_ENABLE_HOOKS

/* for reading files */
#define MAX_PAYLOAD_RULES       1024
#define LINE_BUF_SIZE           4096
/* pcre rule limit */
#define NUM_SUBSTRING_VECTS     60
/* limit the length of strings */
#define MAX_CAPTURE_LENGTH      200
/* max num of DPI fields we'll export - total */
#define YAF_MAX_CAPTURE_FIELDS  50
/* per side */
#define YAF_MAX_CAPTURE_SIDE    25
/* DNS Max Name length */
#define DNS_MAX_NAME_LENGTH     255

/* User Limit on New Labels */
#define USER_LIMIT              10


typedef struct protocolRegexFields_st {
    pcre *rule;
    pcre_extra *extra;
    uint16_t info_element_id;
} protocolRegexFields;

typedef struct protocolRegexRules_st {
    int numRules;
    uint16_t applabel;
    protocolRegexFields regexFields[MAX_PAYLOAD_RULES];
} protocolRegexRules_t;

/* incremement below to add a new protocol - 0 needs to be first */
#define DPI_TOTAL_PROTOCOLS 18

static const uint16_t DPIProtocols[] = {0, 21, 22, 25, 53, 69, 80, 110, 119,
                                        143, 194, 427, 443, 554, 873,
                                        1723, 5060, 3306};
/* export DNSSEC info - NO by default */
static gboolean dnssec = FALSE;

typedef struct DPIActiveHash_st {
    uint16_t     portNumber;
    uint16_t     activated;
    uint8_t      hash;
} DPIActiveHash_t;

/**
 *
 * file globals
 *
 */
static GHashTable *appRuleTable = NULL;
static protocolRegexRules_t ruleSet[DPI_TOTAL_PROTOCOLS + 1];

static char *dpiRulesFileName = NULL;
static unsigned int dpiInitialized = 0;

static DPIActiveHash_t dpiActiveHash[MAX_PAYLOAD_RULES];

static uint16_t dpi_user_limit = MAX_CAPTURE_LENGTH;
static uint16_t dpi_user_total_limit = 1000;

/**
 * the first number is the meta data structure version
 * the second number is the _maximum_ number of bytes the plugin will export
 * the third number is if it requires application labeling (1 for yes)
 */
static struct yfHookMetaData metaData = {
  5,
  1000,
  1
};



/* only will be initialized if we have user-defined elements */
static fbInfoElementSpec_t *yaf_http_extra;
static fbInfoElementSpec_t *yaf_ftp_extra;
static fbInfoElementSpec_t *yaf_imap_extra;
static fbInfoElementSpec_t *yaf_rtsp_extra;
static fbInfoElementSpec_t *yaf_sip_extra;
static fbInfoElementSpec_t *yaf_ssh_extra;
static fbInfoElementSpec_t *yaf_smtp_extra;

static fbTemplate_t *ircTemplate;
static fbTemplate_t *pop3Template;
static fbTemplate_t *tftpTemplate;
static fbTemplate_t *slpTemplate;
static fbTemplate_t *httpTemplate;
static fbTemplate_t *ftpTemplate;
static fbTemplate_t *imapTemplate;
static fbTemplate_t *rtspTemplate;
static fbTemplate_t *sipTemplate;
static fbTemplate_t *smtpTemplate;
static fbTemplate_t *sshTemplate;
static fbTemplate_t *nntpTemplate;
static fbTemplate_t *dnsTemplate;
static fbTemplate_t *dnsQRTemplate;
static fbTemplate_t *dnsATemplate;
static fbTemplate_t *dnsAAAATemplate;
static fbTemplate_t *dnsCNTemplate;
static fbTemplate_t *dnsMXTemplate;
static fbTemplate_t *dnsNSTemplate;
static fbTemplate_t *dnsPTRTemplate;
static fbTemplate_t *dnsTXTTemplate;
static fbTemplate_t *dnsSRVTemplate;
static fbTemplate_t *dnsSOATemplate;
static fbTemplate_t *sslTemplate;
static fbTemplate_t *sslCertTemplate;
static fbTemplate_t *sslSubTemplate;
static fbTemplate_t *mysqlTemplate;
static fbTemplate_t *mysqlTxtTemplate;
static fbTemplate_t *dnsDSTemplate;
static fbTemplate_t *dnsNSEC3Template;
static fbTemplate_t *dnsNSECTemplate;
static fbTemplate_t *dnsRRSigTemplate;
static fbTemplate_t *dnsKeyTemplate;


/**
 *
 *
 */
#ifdef NDEBUG
#define assert(x)
#else
#define assert(x) if (!(x)) { fprintf(stderr,"assertion failed: \"%s\" at line %d of file %s\n",# x, __LINE__, __FILE__); abort(); }
#endif



void yfAlignmentCheck1()
{
    size_t prevOffset = 0;
    size_t prevSize = 0;

#define DO_SIZE(S_,F_) (SIZE_T_CAST)sizeof(((S_ *)(0))->F_)
#define EA_STRING(S_,F_) "alignment error in struct " #S_ " for element "   \
                         #F_ " offset %#"SIZE_T_FORMATX" size %"            \
        SIZE_T_FORMAT" (pad %"SIZE_T_FORMAT")",            \
        (SIZE_T_CAST)offsetof(S_,F_), DO_SIZE(S_,F_),      \
        (SIZE_T_CAST)(offsetof(S_,F_) % DO_SIZE(S_,F_))
#define EG_STRING(S_,F_) "gap error in struct " #S_ " for element " #F_     \
        " offset %#"SIZE_T_FORMATX" size %"SIZE_T_FORMAT,  \
        (SIZE_T_CAST)offsetof(S_,F_),                      \
        DO_SIZE(S_,F_)
#define RUN_CHECKS(S_,F_,A_) {                                  \
        if (((offsetof(S_,F_) % DO_SIZE(S_,F_)) != 0) && A_) {          \
            g_error(EA_STRING(S_,F_));                                  \
        }                                                               \
        if (offsetof(S_,F_) != (prevOffset+prevSize)) {                 \
            g_error(EG_STRING(S_,F_));                                  \
            return;                                                     \
        }                                                               \
        prevOffset = offsetof(S_,F_);                                   \
        prevSize = DO_SIZE(S_,F_);                                      \
        /*fprintf(stderr, "%17s %40s %#5lx %3d %#5lx\n", #S_, #F_,      \
                offsetof(S_,F_), DO_SIZE(S_,F_),                        \
                offsetof(S_,F_)+DO_SIZE(S_,F_));*/                      \
     }

    RUN_CHECKS(yfSSLFlow_t, sslCipherList, 1);
    RUN_CHECKS(yfSSLFlow_t, sslServerCipher, 1);
    RUN_CHECKS(yfSSLFlow_t, sslClientVersion, 1);
    RUN_CHECKS(yfSSLFlow_t, sslCompressionMethod, 1);
    RUN_CHECKS(yfSSLFlow_t, padding, 0);
    RUN_CHECKS(yfSSLFlow_t, sslCertList, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfSSLObjValue_t, obj_value, 1);
    RUN_CHECKS(yfSSLObjValue_t, obj_id, 1);
    RUN_CHECKS(yfSSLObjValue_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfHTTPFlow_t, server, 1);
    RUN_CHECKS(yfHTTPFlow_t, userAgent, 1);
    RUN_CHECKS(yfHTTPFlow_t, get, 1);
    RUN_CHECKS(yfHTTPFlow_t, connection, 1);
    RUN_CHECKS(yfHTTPFlow_t, referer, 1);
    RUN_CHECKS(yfHTTPFlow_t, location, 1);
    RUN_CHECKS(yfHTTPFlow_t, host, 1);
    RUN_CHECKS(yfHTTPFlow_t, contentLength, 1);
    RUN_CHECKS(yfHTTPFlow_t, age, 1);
    RUN_CHECKS(yfHTTPFlow_t, response, 1);
    RUN_CHECKS(yfHTTPFlow_t, acceptLang, 1);
    RUN_CHECKS(yfHTTPFlow_t, accept, 1);
    RUN_CHECKS(yfHTTPFlow_t, contentType, 1);
    RUN_CHECKS(yfHTTPFlow_t, httpVersion, 1);
    RUN_CHECKS(yfHTTPFlow_t, httpCookie, 1);
    RUN_CHECKS(yfHTTPFlow_t, httpSetCookie, 1);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSQRFlow_t, dnsRRList, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsQName, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsTTL, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsQRType, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsQueryResponse, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsAuthoritative, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsNXDomain, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsRRSection, 1);
    RUN_CHECKS(yfDNSQRFlow_t, dnsID, 1);
    RUN_CHECKS(yfDNSQRFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfSSLCertFlow_t, issuer, 1);
    RUN_CHECKS(yfSSLCertFlow_t, subject, 1);
    RUN_CHECKS(yfSSLCertFlow_t, extension, 1);
    RUN_CHECKS(yfSSLCertFlow_t, sig, 1);
    RUN_CHECKS(yfSSLCertFlow_t, serial, 1);
    RUN_CHECKS(yfSSLCertFlow_t, not_before, 1);
    RUN_CHECKS(yfSSLCertFlow_t, not_after, 1);
    RUN_CHECKS(yfSSLCertFlow_t, pkalg, 1);
    RUN_CHECKS(yfSSLCertFlow_t, pklen, 1);
    RUN_CHECKS(yfSSLCertFlow_t, version, 1);
    RUN_CHECKS(yfSSLCertFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSSOAFlow_t, mname, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, rname, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, serial, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, refresh, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, retry, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, expire, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, minimum, 1);
    RUN_CHECKS(yfDNSSOAFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSSRVFlow_t, dnsTarget, 1);
    RUN_CHECKS(yfDNSSRVFlow_t, dnsPriority, 1);
    RUN_CHECKS(yfDNSSRVFlow_t, dnsWeight, 1);
    RUN_CHECKS(yfDNSSRVFlow_t, dnsPort, 1);
    RUN_CHECKS(yfDNSSRVFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSMXFlow_t, exchange, 1);
    RUN_CHECKS(yfDNSMXFlow_t, preference, 1);
    RUN_CHECKS(yfDNSMXFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSDSFlow_t, dnsDigest, 1);
    RUN_CHECKS(yfDNSDSFlow_t, dnsKeyTag, 1);
    RUN_CHECKS(yfDNSDSFlow_t, dnsAlgorithm, 1);
    RUN_CHECKS(yfDNSDSFlow_t, dnsDigestType, 1);
    RUN_CHECKS(yfDNSDSFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSRRSigFlow_t, dnsSigner, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsSignature, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsSigInception, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsSigExp, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsTTL, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsTypeCovered, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsKeyTag, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsAlgorithm, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, dnsLabels, 1);
    RUN_CHECKS(yfDNSRRSigFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSNSECFlow_t, dnsHashData, 1);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSKeyFlow_t, dnsPublicKey, 1);
    RUN_CHECKS(yfDNSKeyFlow_t, dnsFlags, 1);
    RUN_CHECKS(yfDNSKeyFlow_t, protocol, 1);
    RUN_CHECKS(yfDNSKeyFlow_t, dnsAlgorithm, 1);
    RUN_CHECKS(yfDNSKeyFlow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfDNSNSEC3Flow_t, dnsSalt, 1);
    RUN_CHECKS(yfDNSNSEC3Flow_t, dnsNextDomainName, 1);
    RUN_CHECKS(yfDNSNSEC3Flow_t, iterations, 1);
    RUN_CHECKS(yfDNSNSEC3Flow_t, dnsAlgorithm, 1);
    RUN_CHECKS(yfDNSNSEC3Flow_t, padding, 0);

    prevOffset = 0;
    prevSize = 0;

    RUN_CHECKS(yfMySQLFlow_t, mysqlList, 1);
    RUN_CHECKS(yfMySQLFlow_t, mysqlUsername, 1);

    prevOffset = 0;
    prevSize = 0;
    RUN_CHECKS(yfMySQLTxtFlow_t, mysqlCommandText, 1);
    RUN_CHECKS(yfMySQLTxtFlow_t, mysqlCommandCode, 1);
    RUN_CHECKS(yfMySQLTxtFlow_t, padding, 0);

#undef DO_SIZE
#undef EA_STRING
#undef EG_STRING
#undef RUN_CHECKS
}


/**
 * hookInitialize
 *
 *
 * @param err
 *
 */
gboolean ypHookInitialize (
    char             *dpiFQFileName,
    GError           **err)
{
    FILE *dpiRuleFile = NULL;

    if (NULL == dpiFQFileName) {
        dpiFQFileName = YAF_CONF_DIR"/yafDPIRules.conf";
    }

    dpiRuleFile = fopen(dpiFQFileName, "r");
    if (NULL == dpiRuleFile) {
        fprintf(stderr, "Could not open "
                "Deep Packet Inspection Rule File \"%s\" for reading\n",
                dpiFQFileName);
        return FALSE;
    }

    g_debug("Initializing Rules from DPI File %s", dpiFQFileName);
    if (!ypInitializeProtocolRules(dpiRuleFile, err)) {
        return FALSE;
    }
    yfAlignmentCheck1();

    dpiInitialized = 1;
    return TRUE;
}



/**
 * flowAlloc
 *
 * Allocate the hooks struct here, but don't allocate the DPI struct
 * until we want to fill it so we don't have to hold empty memory for long.
 *
 *
 */
void ypFlowAlloc(
    void          **yfHookContext,
    yfFlow_t      *flow)
{

    ypDPIFlowCtx_t *newFlowContext = NULL;

    newFlowContext = (ypDPIFlowCtx_t *)yg_slice_alloc0(sizeof(ypDPIFlowCtx_t));

    newFlowContext->dpinum = 0;
    newFlowContext->startOffset = 0;
    newFlowContext->exbuf = NULL;
    newFlowContext->dpi = NULL;
    *yfHookContext = (void *) newFlowContext;

    return;
}

/**
 * getDPIInfoModel
 *
 *
 *
 * @return a pointer to a fixbuf info model
 *
 */
fbInfoModel_t *ypGetDPIInfoModel()
{
    static fbInfoModel_t *yaf_dpi_model = NULL;
    if (!yaf_dpi_model) {
        yaf_dpi_model = fbInfoModelAlloc();
        fbInfoModelAddElementArray(yaf_dpi_model, yaf_dpi_info_elements);
    }

    (void)yaf_info_elements;
    return yaf_dpi_model;
}


/**
 * flowClose
 *
 *
 * @param flow a pointer to the flow structure that maintains all the flow
 *             context
 *
 */

gboolean ypFlowClose(
    void              *yfHookContext,
    yfFlow_t          *flow)
{

    ypDPIFlowCtx_t      *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    GError              **err = NULL;
    uint8_t             newDPI;

    if (NULL == flowContext) {
        /* log an error here, but how */
        return FALSE;
    }

    if (flowContext->dpi == NULL) {
        flowContext->dpi = yg_slice_alloc0(YAF_MAX_CAPTURE_FIELDS *
                                           sizeof(yfDPIData_t));
    }

    if (dpiInitialized == 0) {
        if (!ypHookInitialize(dpiRulesFileName, err)) {
            return FALSE;
        }
    }

    if (flow->appLabel) {
        /* Do DPI Processing from Rule Files */
        newDPI = ypDPIScanner(flowContext, flow->val.payload, flow->val.paylen,
                              flow, &(flow->val));
        flowContext->captureFwd += newDPI;
        if (flow->rval.paylen) {
            newDPI = ypDPIScanner(flowContext, flow->rval.payload,
                                  flow->rval.paylen, flow, &(flow->rval));
        }
    }

    /*fprintf(stderr, "closing flow %p with context %p\n", flow,flowContext);*/

    return TRUE;
}

/**
 * ypValidateFlowTab
 *
 * returns FALSE if applabel mode is disabled, true otherwise
 *
 */
gboolean ypValidateFlowTab(
    uint32_t        max_payload,
    gboolean        uniflow,
    gboolean        silkmode,
    gboolean        applabelmode,
    gboolean        entropymode,
    gboolean        fingerprintmode,
    gboolean        fpExportMode,
    gboolean        udp_max_payload,
    gboolean        udp_uniflow_mode,
    GError          **err)
{

    if (!applabelmode) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
            "ERROR: dpacketplugin.c will not operate without --applabel");
        return FALSE;
    }

    return TRUE;

}



/**
 * ypSearchPlugOpts
 *
 * check if DPI is turned on for this label
 *
 * @param appLabel
 * @return offset in Rule Array
 *
 */

uint16_t ypSearchPlugOpts (
    uint16_t          appLabel)
{
    uint16_t          rc;

    rc = ypProtocolHashSearch(appLabel, 0);

    return rc;
}

/**
 * ypAddRuleKey
 *
 * @param appLabel
 * @param InfoElementId
 * @param fbBasicList_t*
 * @param fbInfoElement_t *
 */
void ypAddRuleKey(
    uint16_t                appLabel,
    uint16_t                id,
    const fbInfoElement_t   *ie,
    size_t                  bl)
{

    ypBLKey_t               *key = yg_slice_new0(ypBLKey_t);
    ypBLValue_t             *val = NULL;

    key->appLabel = appLabel;
    key->id = id;

    if (!appRuleTable) {
        appRuleTable = g_hash_table_new((GHashFunc)g_int_hash,
                                        (GEqualFunc)g_int_equal);
    }

    val = yg_slice_new0(ypBLValue_t);

    val->BLoffset = bl;
    val->infoElement = ie;

    g_hash_table_insert(appRuleTable, key, val);
}


/**
 * ypGetRule
 *
 * @param appLabel
 * @param infoElementID
 * @return ypBLValue_t
 *
 */
ypBLValue_t *ypGetRule(
    uint16_t               appLabel,
    uint16_t               id)
{

    ypBLValue_t            *val = NULL;
    ypBLKey_t              key;

    key.appLabel = appLabel;
    key.id = id;

    if (!appRuleTable) {
        return NULL;
    }

    val = g_hash_table_lookup(appRuleTable, &key);

    return val;
}

/**
 * ypAddSpec
 *
 * This creates a spec array for each protocol that allow users to add
 * their own basicList elements.  It then adds the given element to that
 * spec array and increments the counter for the amount of elements in the
 * array.  Returns -1 if applabel is not valid.
 *
 * @param spec fbInfoElementSpec_t
 * @param applabel
 * @param offset
 *
 */
int ypAddSpec(
    fbInfoElementSpec_t      *spec,
    uint16_t                 applabel,
    size_t                   *offset)
{

    static int               http_extra = 0;
    static int               imap_extra = 0;
    static int               ftp_extra = 0;
    static int               rtsp_extra = 0;
    static int               sip_extra = 0;
    static int               ssh_extra = 0;
    static int               smtp_extra = 0;

    if (applabel == 80) {

        if (spec) {
            if (!yaf_http_extra) {
                yaf_http_extra = (fbInfoElementSpec_t *)g_malloc0(sizeof(fbInfoElementSpec_t) * USER_LIMIT);
            }
            if (http_extra < USER_LIMIT) {
                memcpy(yaf_http_extra + http_extra, spec,
                       sizeof(fbInfoElementSpec_t));
                http_extra++;
            }
        }
        *offset = offsetof(yfHTTPFlow_t, httpBasicListBuf) +
                  (sizeof(fbBasicList_t) * http_extra);

        return http_extra;

    } else if (applabel == 143) {

        if (spec) {
            if (!yaf_imap_extra) {
                yaf_imap_extra = (fbInfoElementSpec_t *)g_malloc0(sizeof(fbInfoElementSpec_t) * USER_LIMIT);
            }
            if (imap_extra < USER_LIMIT) {
                memcpy(yaf_imap_extra + imap_extra, spec,
                       sizeof(fbInfoElementSpec_t));
                imap_extra++;
            }
        }
        *offset = offsetof(yfIMAPFlow_t, imapBasicListBuf) +
                  (sizeof(fbBasicList_t) * imap_extra);

        return imap_extra;

    } else if (applabel == 21) {
        if (spec) {
            if (!yaf_ftp_extra) {
                yaf_ftp_extra = (fbInfoElementSpec_t *)g_malloc0(sizeof(fbInfoElementSpec_t) * USER_LIMIT);
            }
            if (ftp_extra < USER_LIMIT) {
                memcpy(yaf_ftp_extra + ftp_extra, spec,
                       sizeof(fbInfoElementSpec_t));
                ftp_extra++;
            }
        }
        *offset = offsetof(yfFTPFlow_t, ftpBasicListBuf) +
                  (sizeof(fbBasicList_t) * ftp_extra);

        return ftp_extra;

    } else if (applabel == 22) {

        if (spec) {
            if (!yaf_ssh_extra) {
                yaf_ssh_extra = (fbInfoElementSpec_t *)g_malloc0(sizeof(fbInfoElementSpec_t) * USER_LIMIT);
            }
            if (ssh_extra < USER_LIMIT) {
                memcpy(yaf_ssh_extra + ssh_extra, spec,
                       sizeof(fbInfoElementSpec_t));
                ssh_extra++;
            }
        }

        *offset = offsetof(yfSSHFlow_t, sshBasicListBuf) +
                  (sizeof(fbBasicList_t) * ssh_extra);

        return ssh_extra;

    } else if (applabel == 554) {

        if (spec) {
            if (!yaf_rtsp_extra) {
                yaf_rtsp_extra = (fbInfoElementSpec_t *)g_malloc0(sizeof(fbInfoElementSpec_t) * USER_LIMIT);
            }
            if (rtsp_extra < USER_LIMIT) {
                memcpy(yaf_rtsp_extra +rtsp_extra, spec,
                       sizeof(fbInfoElementSpec_t));
                rtsp_extra++;
            }
        }

        *offset = offsetof(yfRTSPFlow_t, rtspBasicListBuf) +
                  (sizeof(fbBasicList_t) * rtsp_extra);

        return rtsp_extra;

    } else if (applabel == 5060) {

        if (spec) {
            if (!yaf_sip_extra) {
                yaf_sip_extra = (fbInfoElementSpec_t *)g_malloc0(sizeof(fbInfoElementSpec_t) * USER_LIMIT);
            }
            if (sip_extra < USER_LIMIT) {
                memcpy(yaf_sip_extra +sip_extra, spec,
                       sizeof(fbInfoElementSpec_t));
                sip_extra++;
            }
        }

        *offset = offsetof(yfSIPFlow_t, sipBasicListBuf) +
                  (sizeof(fbBasicList_t) * sip_extra);
        return sip_extra;

    } else if (applabel == 25) {

        if (spec) {
            if (!yaf_smtp_extra) {
                yaf_smtp_extra = (fbInfoElementSpec_t *)g_malloc0(sizeof(fbInfoElementSpec_t) * USER_LIMIT);
            }
            if (smtp_extra < USER_LIMIT) {
                memcpy(yaf_smtp_extra +smtp_extra, spec,
                       sizeof(fbInfoElementSpec_t));
                smtp_extra++;
            }
        }

        *offset = offsetof(yfSMTPFlow_t, smtpBasicListBuf) +
                  (sizeof(fbBasicList_t) * smtp_extra);

        return smtp_extra;

    }

    return -1;
}


/**
 * ypInitializeProtocolRules
 *
 * @param dpiRuleFile
 * @param err
 *
 */
gboolean ypInitializeProtocolRules(
    FILE   *dpiRuleFile,
    GError **err)
{

    int        rulePos = 1;
    const char *errorString;
    int        errorPos, rc, readLength, BLoffset;
    int        tempNumRules = 0;
    char       lineBuffer[LINE_BUF_SIZE];
    pcre       *ruleScanner;
    pcre       *commentScanner;
    pcre       *newRuleScanner;
    pcre       *fieldScanner;
    pcre       *totalScanner;
    pcre       *newRule;
    pcre_extra *newExtra;
    const char commentScannerExp[] = "^\\s*#[^\\n]*\\n";
    const char ruleScannerExp[]="^[[:space:]]*label[[:space:]]+([[:digit:]]+)"
        "[[:space:]]+yaf[[:space:]]+([[:digit:]]+)[[:space:]]+"
        "([^\\n].*)\\n";
    const char newRuleScannerExp[]="^[[:space:]]*label[[:space:]]+([[:digit:]]+)"
        "[[:space:]]+user[[:space:]]+([[:digit:]]+)[[:space:]]+"
        "name[[:space:]]+([a-zA-Z0-9_]+)[[:space:]]+([^\\n].*)\\n";
    const char fieldLimitExp[]="^[[:space:]]*limit[[:space:]]+field[[:space:]]+"
                               "([[:digit:]]+)\\n";
    const char totalLimitExp[]="^[[:space:]]*limit[[:space:]]+total[[:space:]]+"
                               "([[:digit:]]+)\\n";
    unsigned int bufferOffset = 0;
    int          currentStartPos = 0;
    int          substringVects[NUM_SUBSTRING_VECTS];
    char         *captString;
    uint16_t     applabel, elem_id;
    int          limit;
    const fbInfoElement_t *elem = NULL;
    fbInfoElementSpec_t spec;
    fbInfoElement_t add_element;
    size_t       struct_offset;
    fbInfoModel_t *model = ypGetDPIInfoModel();

    for (rc = 0; rc < DPI_TOTAL_PROTOCOLS + 1; rc++) {
        ruleSet[rc].numRules = 0;
    }

    ruleScanner = pcre_compile(ruleScannerExp, PCRE_MULTILINE, &errorString,
                               &errorPos, NULL);
    if (ruleScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI Rule Scanner");
        return FALSE;
    }

    commentScanner = pcre_compile(commentScannerExp, PCRE_MULTILINE,
                                  &errorString, &errorPos, NULL);
    if (commentScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI Comment Scanner");
        return FALSE;
    }

    newRuleScanner = pcre_compile(newRuleScannerExp, PCRE_MULTILINE,
                                  &errorString,
                                  &errorPos, NULL);
    if (newRuleScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI New Rule Scanner");
        return FALSE;
    }

    fieldScanner = pcre_compile(fieldLimitExp, PCRE_MULTILINE,
                                &errorString,
                                &errorPos, NULL);
    if (fieldScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI field Limit Scanner");
        return FALSE;
    }

    totalScanner = pcre_compile(totalLimitExp, PCRE_MULTILINE,
                                &errorString,
                                &errorPos, NULL);
    if (totalScanner == NULL) {
        *err = g_error_new(YAF_ERROR_DOMAIN, YAF_ERROR_INTERNAL, "Couldn't "
                           "build the DPI total Limit Scanner");
        return FALSE;
    }

    do {
        readLength = fread(lineBuffer + bufferOffset, 1, LINE_BUF_SIZE - 1 -
                           bufferOffset, dpiRuleFile);
        if (readLength == 0) {
            if (ferror(dpiRuleFile)) {
                *err = g_error_new (YAF_ERROR_DOMAIN, YAF_ERROR_IO,
                                    "Couldn't read the DPI Rule File: %s",
                                    strerror(errno));
                return FALSE;
            }
            break;
        }
        readLength += bufferOffset;
        substringVects[0] = 0;
        substringVects[1] = 0;

        while (substringVects[1] < readLength) {
            if ('\n' == *(lineBuffer + substringVects[1])
                || '\r' == *(lineBuffer + substringVects[1])) {
                substringVects[1]++;
                continue;
            }
            currentStartPos = substringVects[1];
            rc = pcre_exec(commentScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                continue;
            }

            substringVects[1] = currentStartPos;

            rc = pcre_exec(ruleScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                applabel = strtoul(captString, NULL, 10);
                rulePos = ypProtocolHashSearch(applabel, 0);
                if (!rulePos) {
                    /* protocol not turned on */
                    pcre_free(captString);
                    continue;
                }

                pcre_free(captString);
                pcre_get_substring(lineBuffer, substringVects, rc, 2,
                                   (const char **)&captString);
                elem_id = strtoul(captString, NULL, 10);

                if (!(elem = fbInfoModelGetElementByID(model, elem_id, 6871))) {
                    g_warning("Element %d does not exist in Info Model.  "
                              "Please add Element to Model or use the "
                              "'new element' rule", elem_id);
                    continue;
                }
                ruleSet[rulePos].applabel = applabel;
                ruleSet[rulePos].regexFields[ruleSet[rulePos].numRules].info_element_id =
                    elem_id;
                pcre_free(captString);
                pcre_get_substring(lineBuffer, substringVects, rc, 3,
                                   (const char**)&captString);

                newRule = pcre_compile(captString, PCRE_MULTILINE,
                                       &errorString, &errorPos, NULL);
                if (NULL == newRule) {
                    g_warning("Error Parsing DPI Rule \"%s\"", captString);
                } else {
                    newExtra = pcre_study(newRule, 0, &errorString);
                    ruleSet[rulePos].regexFields[ruleSet[rulePos].numRules].rule = newRule;
                    ruleSet[rulePos].regexFields[ruleSet[rulePos].numRules].extra = newExtra;
                    ruleSet[rulePos].numRules++;
                    tempNumRules++;
                }

                pcre_free(captString);

                if (MAX_PAYLOAD_RULES == ruleSet[rulePos].numRules) {
                    g_warning("Maximum number of rules has been reached "
                              "within DPI Plugin");
                    break;
                }

                continue;
            }
            substringVects[1] = currentStartPos;

            rc = pcre_exec(newRuleScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                applabel = strtoul(captString, NULL, 10);
                rulePos = ypProtocolHashSearch(applabel, 0);
                if (!rulePos) {
                    /* protocol not turned on */
                    pcre_free(captString);
                    continue;
                }
                ruleSet[rulePos].applabel = applabel;

                pcre_free(captString);
                pcre_get_substring(lineBuffer, substringVects, rc, 2,
                                   (const char **)&captString);
                elem_id = strtoul(captString, NULL, 10);
                pcre_free(captString);
                pcre_get_substring(lineBuffer, substringVects, rc, 3,
                                   (const char**)&captString);
                if (!(elem = fbInfoModelGetElementByID(model, elem_id, 6871))){
                    add_element.num = elem_id;
                    add_element.ent = 6871;
                    add_element.len = FB_IE_VARLEN;
                    add_element.ref.name = captString;
                    add_element.midx = 0;
                    add_element.flags = 0;
                    BLoffset = ypAddSpec(NULL, applabel, &struct_offset);
                    if (BLoffset == -1) {
                        g_warning("NOT adding element for label %d.",applabel);
                        continue;
                    } else if (BLoffset < USER_LIMIT) {
                        fbInfoModelAddElement(model, &add_element);
                        ypAddRuleKey(applabel, elem_id,
                             fbInfoModelGetElementByName(model, captString),
                                     struct_offset);
                        spec.len_override = 0;
                        spec.name = "basicList";
                        spec.flags = 0;
                        ypAddSpec(&spec, applabel, &struct_offset);
                    } else {
                        g_warning("LIMIT Exceeded. Element %s with ID %d "
                                  "was not added.", captString, elem_id);
                        continue;
                    }
                }
                ruleSet[rulePos].regexFields[ruleSet[rulePos].numRules].info_element_id = elem_id;
                pcre_free(captString);
                pcre_get_substring(lineBuffer, substringVects, rc, 4,
                                       (const char**)&captString);

                newRule = pcre_compile(captString, PCRE_MULTILINE,
                                       &errorString, &errorPos, NULL);
                if (NULL == newRule) {
                    g_warning("Error Parsing DPI Rule \"%s\"", captString);
                } else {
                    newExtra = pcre_study(newRule, 0, &errorString);
                    ruleSet[rulePos].regexFields[ruleSet[rulePos].numRules].rule = newRule;
                    ruleSet[rulePos].regexFields[ruleSet[rulePos].numRules].extra = newExtra;
                    ruleSet[rulePos].numRules++;
                    tempNumRules++;
                }

                pcre_free(captString);

                if (MAX_PAYLOAD_RULES == ruleSet[rulePos].numRules) {
                    g_warning("Maximum number of rules has been reached "
                              "within DPI Plugin");
                    break;
                }

                continue;
            }

            substringVects[1] = currentStartPos;
            rc = pcre_exec(fieldScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                limit = strtoul(captString, NULL, 10);
                if (limit > 65535) {
                    g_warning("Per Field Limit is Too Large (%d), Setting to Default.", limit);
                    limit = MAX_CAPTURE_LENGTH;
                }
                dpi_user_limit = limit;
                pcre_free(captString);
                continue;
            }
            substringVects[1] = currentStartPos;

            rc = pcre_exec(totalScanner, NULL, lineBuffer, readLength,
                           substringVects[1], PCRE_ANCHORED, substringVects,
                           NUM_SUBSTRING_VECTS);
            if (rc > 0) {
                pcre_get_substring(lineBuffer, substringVects, rc, 1,
                                   (const char **)&captString);
                limit = strtoul(captString, NULL, 10);
                if (limit > 65535) {
                    g_warning("Total Limit is Too Large (%d), Setting to Default.", limit);
                    limit = 1000;
                }
                dpi_user_total_limit = limit;
                pcre_free(captString);
                continue;
            }

            substringVects[1] = currentStartPos;

            if ((PCRE_ERROR_NOMATCH == rc) && (substringVects[1] < readLength)
                && !feof (dpiRuleFile)) {
                memmove (lineBuffer, lineBuffer + substringVects[1],
                         readLength - substringVects[1]);
                bufferOffset = readLength - substringVects[1];
                break;
            } else if (PCRE_ERROR_NOMATCH == rc && feof(dpiRuleFile)) {
                g_critical("Unparsed text at the end of the DPI Rule File!\n");
                break;
            }
        }

    } while (!ferror(dpiRuleFile) && !feof(dpiRuleFile));


    g_debug("DPI rule scanner accepted %d rules from the DPI Rule File",
            tempNumRules);

    pcre_free(ruleScanner);
    pcre_free(commentScanner);
    pcre_free(newRuleScanner);
    pcre_free(totalScanner);
    pcre_free(fieldScanner);
    return TRUE;
}

/**
 * flowFree
 *
 *
 * @param flow pointer to the flow structure with the context information
 *
 *
 */
void ypFlowFree(
    void             *yfHookContext,
    yfFlow_t         *flow)
{

    ypDPIFlowCtx_t   *flowContext = (ypDPIFlowCtx_t *)yfHookContext;

    if (NULL == flowContext) {
        /* log an error here, but how */
        g_warning("couldn't free flow %p; not in hash table\n", flow);
        return;
    }

    if (flowContext->dpi) {
        yg_slice_free1((sizeof(yfDPIData_t) * YAF_MAX_CAPTURE_FIELDS),
                       flowContext->dpi);
    }

    yg_slice_free1(sizeof(ypDPIFlowCtx_t), flowContext);

    return;
}


/**
 * hookPacket
 *
 * allows the plugin to examine the start of a flow capture and decide if a
 * flow capture should be dropped from processing
 *
 * @param key
 * @param pkt
 * @param caplen
 * @param iplen
 * @param tcpinfo
 * @param l2info
 *
 * @return TRUE to continue tracking this flow, false to drop tracking the flow
 *
 */
gboolean ypHookPacket(
    yfFlowKey_t          *key,
    const uint8_t        *pkt,
    size_t               caplen,
    uint16_t             iplen,
    yfTCPInfo_t          *tcpinfo,
    yfL2Info_t           *l2info)
{
    /* this never decides to drop packet flow */

    return TRUE;
}


/**
 * flowPacket
 *
 * gets called whenever a packet gets processed, relevant to the given flow
 *
 * DPI uses this in yafApplabel.c
 *
 * @param flow
 * @param val
 * @param pkt
 * @param caplen
 *
 *
 */

void ypFlowPacket(
    void                 *yfHookContext,
    yfFlow_t             *flow,
    yfFlowVal_t          *val,
    const uint8_t        *pkt,
    size_t               caplen,
    uint16_t             iplen,
    yfTCPInfo_t          *tcpinfo,
    yfL2Info_t           *l2info)
{

    ypDPIFlowCtx_t       *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    uint16_t             tempAppLabel = 0;


    if (NULL == flowContext || iplen) {
        /* iplen should only be 0 if yafApplabel is calling this fn */
        return;
    }

    flowContext->captureFwd = flowContext->dpinum;

    if (flowContext->captureFwd > YAF_MAX_CAPTURE_SIDE) {
        /* Max out at 25 per side  - usually won't happen in this case*/
        flowContext->dpinum = YAF_MAX_CAPTURE_SIDE;
        flowContext->captureFwd = YAF_MAX_CAPTURE_SIDE;
    }


    if (caplen && (flow->appLabel > 0)) {
        /* call to applabel's scan payload */
        tempAppLabel = ycScanPayload(pkt, caplen, flow, val);
    }

    /* If we pick up captures from another appLabel it messes with lists */
    if ((tempAppLabel != flow->appLabel)) {
        flowContext->dpinum = flowContext->captureFwd;
    }

    return;
}

/**
 * ypAddHTTPRules
 *
 * Add all rules to Hash Table for Quicker Retrieval
 */
void ypAddHTTPRules(
    ypDPIFlowCtx_t *ctx)
{
    fbInfoModel_t *model = ypGetDPIInfoModel();

    ypAddRuleKey(80,110,fbInfoModelGetElementByName(model, "httpServerString"),
                 offsetof(yfHTTPFlow_t, server));
    ypAddRuleKey(80, 111, fbInfoModelGetElementByName(model, "httpUserAgent"),
                 offsetof(yfHTTPFlow_t, userAgent));
    ypAddRuleKey(80, 112, fbInfoModelGetElementByName(model, "httpGet"),
                 offsetof(yfHTTPFlow_t, get));
    ypAddRuleKey(80, 113, fbInfoModelGetElementByName(model, "httpConnection"),
                 offsetof(yfHTTPFlow_t,connection));
    ypAddRuleKey(80, 115, fbInfoModelGetElementByName(model, "httpReferer"),
                 offsetof(yfHTTPFlow_t, referer));
    ypAddRuleKey(80, 116, fbInfoModelGetElementByName(model, "httpLocation"),
                 offsetof(yfHTTPFlow_t, location));
    ypAddRuleKey(80, 117, fbInfoModelGetElementByName(model, "httpHost"),
                 offsetof(yfHTTPFlow_t, host));
    ypAddRuleKey(80,118,fbInfoModelGetElementByName(model,"httpContentLength"),
                 offsetof(yfHTTPFlow_t, contentLength));
    ypAddRuleKey(80, 119, fbInfoModelGetElementByName(model, "httpAge"),
                 offsetof(yfHTTPFlow_t, age));
    ypAddRuleKey(80, 123, fbInfoModelGetElementByName(model, "httpResponse"),
                 offsetof(yfHTTPFlow_t, response));
    ypAddRuleKey(80, 121,
                 fbInfoModelGetElementByName(model,"httpAcceptLanguage"),
                 offsetof(yfHTTPFlow_t, acceptLang));
    ypAddRuleKey(80, 120, fbInfoModelGetElementByName(model, "httpAccept"),
                 offsetof(yfHTTPFlow_t, accept));
    ypAddRuleKey(80, 122,fbInfoModelGetElementByName(model, "httpContentType"),
                 offsetof(yfHTTPFlow_t, contentType));
    ypAddRuleKey(80, 114, fbInfoModelGetElementByName(model, "httpVersion"),
                 offsetof(yfHTTPFlow_t, httpVersion));
    ypAddRuleKey(80, 220, fbInfoModelGetElementByName(model, "httpCookie"),
                 offsetof(yfHTTPFlow_t, httpCookie));
    ypAddRuleKey(80, 221, fbInfoModelGetElementByName(model, "httpSetCookie"),
                 offsetof(yfHTTPFlow_t, httpSetCookie));

}
/**
 * ypAddRTSPRules
 *
 * add all rules to hash table for quick retrieval
 *
 */
void ypAddRTSPRules(
    ypDPIFlowCtx_t *ctx)
{
    fbInfoModel_t *model = ypGetDPIInfoModel();

    ypAddRuleKey(554, 143, fbInfoModelGetElementByName(model, "rtspURL"),
                 offsetof(yfRTSPFlow_t, rtspURL));
    ypAddRuleKey(554, 144, fbInfoModelGetElementByName(model, "rtspVersion"),
                 offsetof(yfRTSPFlow_t, rtspVersion));
    ypAddRuleKey(554, 145,fbInfoModelGetElementByName(model, "rtspReturnCode"),
                 offsetof(yfRTSPFlow_t, rtspReturnCode));
    ypAddRuleKey(554, 146,
                 fbInfoModelGetElementByName(model, "rtspContentLength"),
                 offsetof(yfRTSPFlow_t, rtspContentLength));
    ypAddRuleKey(554, 147, fbInfoModelGetElementByName(model, "rtspCommand"),
                 offsetof(yfRTSPFlow_t, rtspCommand));
    ypAddRuleKey(554,148,fbInfoModelGetElementByName(model, "rtspContentType"),
                 offsetof(yfRTSPFlow_t, rtspContentType));
    ypAddRuleKey(554, 149, fbInfoModelGetElementByName(model, "rtspTransport"),
                 offsetof(yfRTSPFlow_t, rtspTransport));
    ypAddRuleKey(554, 150, fbInfoModelGetElementByName(model, "rtspCSeq"),
                 offsetof(yfRTSPFlow_t, rtspCSeq));
    ypAddRuleKey(554, 151, fbInfoModelGetElementByName(model, "rtspLocation"),
                 offsetof(yfRTSPFlow_t, rtspLocation));
    ypAddRuleKey(554, 152,
                 fbInfoModelGetElementByName(model, "rtspPacketsReceived"),
                 offsetof(yfRTSPFlow_t, rtspPacketsReceived));
    ypAddRuleKey(554, 153, fbInfoModelGetElementByName(model, "rtspUserAgent"),
                 offsetof(yfRTSPFlow_t, rtspUserAgent));
    ypAddRuleKey(554, 154, fbInfoModelGetElementByName(model, "rtspJitter"),
                 offsetof(yfRTSPFlow_t, rtspJitter));
}
/**
 * ypAddFTPRules
 *
 * add all rules to hash table for quick retrieval
 *
 */
void ypAddFTPRules(
    ypDPIFlowCtx_t *ctx)
{
    fbInfoModel_t *model = ypGetDPIInfoModel();

    ypAddRuleKey(21, 131, fbInfoModelGetElementByName(model, "ftpReturn"),
                 offsetof(yfFTPFlow_t, ftpReturn));
    ypAddRuleKey(21, 132, fbInfoModelGetElementByName(model, "ftpUser"),
                 offsetof(yfFTPFlow_t, ftpUser));
    ypAddRuleKey(21, 133, fbInfoModelGetElementByName(model, "ftpPass"),
                 offsetof(yfFTPFlow_t, ftpPass));
    ypAddRuleKey(21, 134, fbInfoModelGetElementByName(model, "ftpType"),
                 offsetof(yfFTPFlow_t, ftpType));
    ypAddRuleKey(21, 135, fbInfoModelGetElementByName(model, "ftpRespCode"),
                 offsetof(yfFTPFlow_t, ftpRespCode));
}

/**
 * ypAddIMAPRules
 *
 * add all rules to hash table for quick retrieval
 *
 */
void ypAddIMAPRules(
    ypDPIFlowCtx_t *ctx)
{

    fbInfoModel_t *model = ypGetDPIInfoModel();

    ypAddRuleKey(143,136, fbInfoModelGetElementByName(model, "imapCapability"),
                 offsetof(yfIMAPFlow_t, imapCapability));
    ypAddRuleKey(143, 137, fbInfoModelGetElementByName(model, "imapLogin"),
                 offsetof(yfIMAPFlow_t, imapLogin));
    ypAddRuleKey(143, 138, fbInfoModelGetElementByName(model, "imapStartTLS"),
                 offsetof(yfIMAPFlow_t, imapStartTLS));
    ypAddRuleKey(143,139,fbInfoModelGetElementByName(model,"imapAuthenticate"),
                 offsetof(yfIMAPFlow_t, imapAuthenticate));
    ypAddRuleKey(143, 140, fbInfoModelGetElementByName(model, "imapCommand"),
                 offsetof(yfIMAPFlow_t, imapCommand));
    ypAddRuleKey(143, 141, fbInfoModelGetElementByName(model, "imapExists"),
                 offsetof(yfIMAPFlow_t, imapExists));
    ypAddRuleKey(143, 142, fbInfoModelGetElementByName(model, "imapRecent"),
                 offsetof(yfIMAPFlow_t, imapRecent));
}
/**
 * ypAddSIPRules
 *
 * add all rules to hash table for quick retrieval
 *
 */
void ypAddSIPRules(
    ypDPIFlowCtx_t *ctx)
{
    fbInfoModel_t *model = ypGetDPIInfoModel();

    ypAddRuleKey(5060, 155, fbInfoModelGetElementByName(model, "sipInvite"),
                 offsetof(yfSIPFlow_t, sipInvite));
    ypAddRuleKey(5060, 156, fbInfoModelGetElementByName(model, "sipCommand"),
                 offsetof(yfSIPFlow_t, sipCommand));
    ypAddRuleKey(5060, 157, fbInfoModelGetElementByName(model, "sipVia"),
                 offsetof(yfSIPFlow_t, sipVia));
    ypAddRuleKey(5060,158,fbInfoModelGetElementByName(model, "sipMaxForwards"),
                 offsetof(yfSIPFlow_t, sipMaxForwards));
    ypAddRuleKey(5060, 159, fbInfoModelGetElementByName(model, "sipAddress"),
                 offsetof(yfSIPFlow_t, sipAddress));
    ypAddRuleKey(5060, 160, fbInfoModelGetElementByName(model, "sipContentLength"), offsetof(yfSIPFlow_t, sipContentLength));
    ypAddRuleKey(5060, 161, fbInfoModelGetElementByName(model, "sipUserAgent"),
                 offsetof(yfSIPFlow_t, sipUserAgent));
}
/**
 * ypAddSSHRules
 *
 */
void ypAddSSHRules(
    ypDPIFlowCtx_t *ctx)
{
    fbInfoModel_t *model = ypGetDPIInfoModel();

    ypAddRuleKey(22, 171, fbInfoModelGetElementByName(model, "sshVersion"),
                 offsetof(yfSSHFlow_t, sshVersion));
}

/**
 * ypAddSMTPRules
 *
 * add all rules to hash table for quick retrieval
 *
 */
void ypAddSMTPRules(
    ypDPIFlowCtx_t *ctx)
{
    fbInfoModel_t *model = ypGetDPIInfoModel();
    ypAddRuleKey(25, 162, fbInfoModelGetElementByName(model, "smtpHello"),
                 offsetof(yfSMTPFlow_t, smtpHello));
    ypAddRuleKey(25, 163, fbInfoModelGetElementByName(model, "smtpFrom"),
                 offsetof(yfSMTPFlow_t, smtpFrom));
    ypAddRuleKey(25, 164, fbInfoModelGetElementByName(model, "smtpTo"),
                 offsetof(yfSMTPFlow_t, smtpTo));
    ypAddRuleKey(25,165, fbInfoModelGetElementByName(model, "smtpContentType"),
                 offsetof(yfSMTPFlow_t, smtpContentType));
    ypAddRuleKey(25, 166, fbInfoModelGetElementByName(model, "smtpSubject"),
                 offsetof(yfSMTPFlow_t, smtpSubject));
    ypAddRuleKey(25, 167, fbInfoModelGetElementByName(model, "smtpFilename"),
                 offsetof(yfSMTPFlow_t, smtpFilename));
    ypAddRuleKey(25, 168,
                 fbInfoModelGetElementByName(model, "smtpContentDisposition"),
                 offsetof(yfSMTPFlow_t, smtpContentDisposition));
    ypAddRuleKey(25, 169, fbInfoModelGetElementByName(model, "smtpResponse"),
                 offsetof(yfSMTPFlow_t, smtpResponse));
    ypAddRuleKey(25, 170, fbInfoModelGetElementByName(model, "smtpEnhanced"),
                 offsetof(yfSMTPFlow_t, smtpEnhanced));
    ypAddRuleKey(25, 222, fbInfoModelGetElementByName(model, "smtpSize"),
                 offsetof(yfSMTPFlow_t, smtpSize));
    ypAddRuleKey(25, 251, fbInfoModelGetElementByName(model, "smtpDate"),
                 offsetof(yfSMTPFlow_t, smtpDate));
}

/**
 * ypInitializeSSHBL
 *
 *
 */
void ypInitializeSSHBL(
    yfSSHFlow_t        **rec)
{
    fbInfoModel_t      *model = ypGetDPIInfoModel();
    fbBasicList_t      *temp = (fbBasicList_t *)(*rec)->sshBasicListBuf;
    int                rc, loop;
    size_t             offset;

    fbBasicListInit(&((*rec)->sshVersion), 0,
                    fbInfoModelGetElementByName(model, "sshVersion"), 0);

    rc = ypAddSpec(NULL, 22, &offset);
    for (loop = 0; loop < rc; loop++) {
        fbBasicListInit(temp, 0,
                        fbInfoModelGetElementByName(model, "sshVersion"), 0);
        temp++;
    }
}
/**
 * ypInitializeSMTPBL
 *
 *
 */
void ypInitializeSMTPBL(
    yfSMTPFlow_t        **rec)
{
    fbInfoModel_t       *model = ypGetDPIInfoModel();
    fbBasicList_t       *temp = (fbBasicList_t *)(*rec)->smtpBasicListBuf;
    int                 rc, loop;
    size_t              offset;

    fbBasicListInit(&((*rec)->smtpHello), 0,
                    fbInfoModelGetElementByName(model, "smtpHello"), 0);
    fbBasicListInit(&((*rec)->smtpFrom), 0,
                    fbInfoModelGetElementByName(model, "smtpFrom"), 0);
    fbBasicListInit(&((*rec)->smtpTo), 0,
                    fbInfoModelGetElementByName(model, "smtpTo"), 0);
    fbBasicListInit(&((*rec)->smtpContentType), 0,
                    fbInfoModelGetElementByName(model, "smtpContentType"), 0);
    fbBasicListInit(&((*rec)->smtpSubject), 0,
                    fbInfoModelGetElementByName(model, "smtpSubject"), 0);
    fbBasicListInit(&((*rec)->smtpFilename), 0,
                    fbInfoModelGetElementByName(model, "smtpFilename"), 0);
    fbBasicListInit(&((*rec)->smtpContentDisposition), 0,
              fbInfoModelGetElementByName(model, "smtpContentDisposition"), 0);
    fbBasicListInit(&((*rec)->smtpResponse), 0,
                    fbInfoModelGetElementByName(model, "smtpResponse"), 0);
    fbBasicListInit(&((*rec)->smtpEnhanced), 0,
                    fbInfoModelGetElementByName(model, "smtpEnhanced"), 0);
    fbBasicListInit(&((*rec)->smtpSize), 0,
                    fbInfoModelGetElementByName(model, "smtpSize"), 0);
    fbBasicListInit(&((*rec)->smtpDate), 0,
                    fbInfoModelGetElementByName(model, "smtpDate"), 0);


    rc = ypAddSpec(NULL, 25, &offset);
    for (loop = 0; loop < rc; loop++) {
        fbBasicListInit(temp, 0, fbInfoModelGetElementByName(model, "smtpTo"),
                        0);
        temp++;
    }
}

/**
 * ypInitializeSIPBL
 *
 *
 */
void ypInitializeSIPBL(
    yfSIPFlow_t         **rec)
{
    fbInfoModel_t       *model = ypGetDPIInfoModel();
    fbBasicList_t       *temp= (fbBasicList_t *)(*rec)->sipBasicListBuf;
    int                 rc, loop;
    size_t              offset;

    fbBasicListInit(&((*rec)->sipInvite), 0,
                    fbInfoModelGetElementByName(model, "sipInvite"), 0);
    fbBasicListInit(&((*rec)->sipCommand), 0,
                    fbInfoModelGetElementByName(model, "sipCommand"), 0);
    fbBasicListInit(&((*rec)->sipVia), 0,
                    fbInfoModelGetElementByName(model, "sipVia"), 0);
    fbBasicListInit(&((*rec)->sipMaxForwards), 0,
                    fbInfoModelGetElementByName(model, "sipMaxForwards"), 0);
    fbBasicListInit(&((*rec)->sipAddress), 0,
                    fbInfoModelGetElementByName(model, "sipAddress"), 0);
    fbBasicListInit(&((*rec)->sipContentLength), 0,
                    fbInfoModelGetElementByName(model, "sipContentLength"), 0);
    fbBasicListInit(&((*rec)->sipUserAgent), 0,
                    fbInfoModelGetElementByName(model, "sipUserAgent"), 0);

    rc = ypAddSpec(NULL, 5060, &offset);
    for(loop = 0; loop < rc; loop++) {
        fbBasicListInit(temp, 0, fbInfoModelGetElementByName(model, "sipVia"),
                        0);
        temp++;
    }

}

/**
 * ypInitializeIMAPBL
 *
 */
void ypInitializeIMAPBL(
    yfIMAPFlow_t          **rec)
{
    fbInfoModel_t         *model = ypGetDPIInfoModel();
    fbBasicList_t         *temp= (fbBasicList_t *)(*rec)->imapBasicListBuf;
    int                   rc, loop;
    size_t                offset;

    fbBasicListInit(&((*rec)->imapCapability), 0,
                    fbInfoModelGetElementByName(model, "imapCapability"), 0);
    fbBasicListInit(&((*rec)->imapLogin), 0,
                    fbInfoModelGetElementByName(model, "imapLogin"), 0);
    fbBasicListInit(&((*rec)->imapStartTLS), 0,
                    fbInfoModelGetElementByName(model, "imapStartTLS"), 0);
    fbBasicListInit(&((*rec)->imapAuthenticate), 0,
                    fbInfoModelGetElementByName(model, "imapAuthenticate"), 0);
    fbBasicListInit(&((*rec)->imapCommand), 0,
                    fbInfoModelGetElementByName(model, "imapCommand"), 0);
    fbBasicListInit(&((*rec)->imapExists), 0,
                    fbInfoModelGetElementByName(model, "imapExists"), 0);
    fbBasicListInit(&((*rec)->imapRecent), 0,
                    fbInfoModelGetElementByName(model, "imapRecent"), 0);

    rc = ypAddSpec(NULL, 143, &offset);
    for (loop = 0; loop < rc; loop++) {
        fbBasicListInit(temp, 0,
                        fbInfoModelGetElementByName(model, "imapLogin"), 0);
        temp++;
    }
}
/**
 * ypInitializeHTTPBL
 *
 */
void ypInitializeHTTPBL(
    yfHTTPFlow_t         **rec)
{

    fbInfoModel_t        *model = ypGetDPIInfoModel();
    fbBasicList_t        *temp = (fbBasicList_t *)(*rec)->httpBasicListBuf;
    int                  rc, loop;
    size_t               offset;


    fbBasicListInit(&((*rec)->server), 0,
                    fbInfoModelGetElementByName(model, "httpServerString"), 0);
    fbBasicListInit(&((*rec)->userAgent), 0,
                    fbInfoModelGetElementByName(model, "httpUserAgent"), 0);
    fbBasicListInit(&((*rec)->get), 0,
                    fbInfoModelGetElementByName(model, "httpGet"), 0);
    fbBasicListInit(&((*rec)->connection), 0,
                    fbInfoModelGetElementByName(model, "httpConnection"), 0);
    fbBasicListInit(&((*rec)->referer), 0,
                    fbInfoModelGetElementByName(model, "httpReferer"), 0);
    fbBasicListInit(&((*rec)->location), 0,
                    fbInfoModelGetElementByName(model, "httpLocation"), 0);
    fbBasicListInit(&((*rec)->host), 0,
                    fbInfoModelGetElementByName(model, "httpHost"), 0);
    fbBasicListInit(&((*rec)->contentLength), 0,
                   fbInfoModelGetElementByName(model, "httpContentLength"), 0);
    fbBasicListInit(&((*rec)->age), 0,
                    fbInfoModelGetElementByName(model, "httpAge"), 0);
    fbBasicListInit(&((*rec)->response), 0,
                    fbInfoModelGetElementByName(model, "httpResponse"), 0);
    fbBasicListInit(&((*rec)->acceptLang), 0,
                  fbInfoModelGetElementByName(model, "httpAcceptLanguage"), 0);
    fbBasicListInit(&((*rec)->accept), 0,
                    fbInfoModelGetElementByName(model, "httpAccept"), 0);
    fbBasicListInit(&((*rec)->httpVersion), 0,
                    fbInfoModelGetElementByName(model, "httpVersion"), 0);
    fbBasicListInit(&((*rec)->contentType), 0,
                    fbInfoModelGetElementByName(model, "httpContentType"), 0);
    fbBasicListInit(&((*rec)->age), 0,
                    fbInfoModelGetElementByName(model, "httpAge"), 0);
    fbBasicListInit(&((*rec)->httpCookie), 0,
                    fbInfoModelGetElementByName(model, "httpCookie"), 0);
    fbBasicListInit(&((*rec)->httpSetCookie), 0,
                    fbInfoModelGetElementByName(model, "httpSetCookie"), 0);

    rc = ypAddSpec(NULL, 80, &offset);
    /* Initialize any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListInit(temp, 0,
                        fbInfoModelGetElementByName(model, "httpVersion"), 0);
        temp++;
    }

}

/**
 * ypInitializeRTSPBL
 *
 */
void ypInitializeRTSPBL(
    yfRTSPFlow_t        **rec)
{
    fbInfoModel_t       *model = ypGetDPIInfoModel();
    fbBasicList_t       *temp = (fbBasicList_t *)(*rec)->rtspBasicListBuf;
    int                 rc, loop;
    size_t              offset;

    fbBasicListInit(&((*rec)->rtspURL), 0,
                    fbInfoModelGetElementByName(model, "rtspURL"), 0);
    fbBasicListInit(&((*rec)->rtspVersion), 0,
                    fbInfoModelGetElementByName(model, "rtspVersion"), 0);
    fbBasicListInit(&((*rec)->rtspReturnCode), 0,
                    fbInfoModelGetElementByName(model, "rtspReturnCode"), 0);
    fbBasicListInit(&((*rec)->rtspContentLength), 0,
                   fbInfoModelGetElementByName(model, "rtspContentLength"), 0);
    fbBasicListInit(&((*rec)->rtspCommand), 0,
                    fbInfoModelGetElementByName(model, "rtspCommand"), 0);
    fbBasicListInit(&((*rec)->rtspContentType), 0,
                    fbInfoModelGetElementByName(model, "rtspContentType"), 0);
    fbBasicListInit(&((*rec)->rtspTransport), 0,
                    fbInfoModelGetElementByName(model, "rtspTransport"), 0);
    fbBasicListInit(&((*rec)->rtspLocation), 0,
                    fbInfoModelGetElementByName(model, "rtspLocation"), 0);
    fbBasicListInit(&((*rec)->rtspCSeq), 0,
                    fbInfoModelGetElementByName(model, "rtspCSeq"), 0);
    fbBasicListInit(&((*rec)->rtspPacketsReceived), 0,
                 fbInfoModelGetElementByName(model, "rtspPacketsReceived"), 0);
    fbBasicListInit(&((*rec)->rtspUserAgent), 0,
                    fbInfoModelGetElementByName(model, "rtspUserAgent"), 0);
    fbBasicListInit(&((*rec)->rtspJitter), 0,
                    fbInfoModelGetElementByName(model, "rtspJitter"), 0);

    rc = ypAddSpec(NULL, 554, &offset);
    /* Initialize any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListInit(temp, 0,
                        fbInfoModelGetElementByName(model, "rtspJitter"), 0);
        temp++;
    }

}

/**
 * ypInitializeFTPBL
 *
 *
 */
void ypInitializeFTPBL(
    yfFTPFlow_t        **rec)
{
    fbInfoModel_t      *model = ypGetDPIInfoModel();
    fbBasicList_t      *temp = (fbBasicList_t *)(*rec)->ftpBasicListBuf;
    int                rc, loop;
    size_t             offset;

    fbBasicListInit(&((*rec)->ftpReturn), 0,
                    fbInfoModelGetElementByName(model, "ftpReturn"), 0);
    fbBasicListInit(&((*rec)->ftpUser), 0,
                    fbInfoModelGetElementByName(model, "ftpUser"), 0);
    fbBasicListInit(&((*rec)->ftpPass), 0,
                    fbInfoModelGetElementByName(model, "ftpPass"), 0);
    fbBasicListInit(&((*rec)->ftpType), 0,
                    fbInfoModelGetElementByName(model, "ftpType"), 0);
    fbBasicListInit(&((*rec)->ftpRespCode), 0,
                    fbInfoModelGetElementByName(model, "ftpRespCode"), 0);

    rc = ypAddSpec(NULL, 21, &offset);
    /* Initialize any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListInit(temp, 0,
                        fbInfoModelGetElementByName(model, "ftpUser"), 0);
        temp++;
    }

}

/**
 * flowWrite
 *
 *  this function gets called when the flow data is getting serialized to be
 *  written into ipfix format.  This function must put its data into the
 *  output stream (rec) in the order that it allocated the data according to
 *  its template model - For DPI it uses IPFIX lists to allocate new
 *  subTemplates in YAF's main subTemplateMultiList
 *
 * @param rec
 * @param rec_sz
 * @param flow
 * @param err
 *
 * @return FALSE if closing the flow should be delayed, TRUE if the data is
 *         available and the flow can be closed
 *
 */
gboolean ypFlowWrite(
    void                           *yfHookContext,
    fbSubTemplateMultiList_t       *rec,
    fbSubTemplateMultiListEntry_t  *stml,
    yfFlow_t                       *flow,
    GError                         **err)
{
    ypDPIFlowCtx_t            *flowContext = (ypDPIFlowCtx_t *)yfHookContext;
    uint16_t                   rc;

    if (NULL == flowContext) {
        g_set_error(err, YAF_ERROR_DOMAIN, YAF_ERROR_IMPL,
            "Unknown plugin flow %p", flow);
        return FALSE;
    }

    if (flowContext->dpinum == 0) {
        /* Nothing to write! */
        return TRUE;
    }

    /*If there's no reverse payload & No Fwd captures this has to be uniflow*/
    if (!flow->rval.payload && !flowContext->captureFwd) {
        flowContext->startOffset = flowContext->captureFwd;
        flowContext->captureFwd = flowContext->dpinum;
        return TRUE;
    }

    /* make sure we have data to write */
    if ((flowContext->startOffset >= flowContext->dpinum))
    {
        return TRUE;
    }

    /* make sure DPI is turned on for this protocol */
    rc = ypSearchPlugOpts(flow->appLabel);
    if (!rc) {
        return TRUE;
    }

    switch(flow->appLabel) {
    case 21:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessFTP(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
    case 22:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessSSH(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
    case 25:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessSMTP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
    case 53:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessDNS(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
    case 69:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessTFTP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
    case 80:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessHTTP(flowContext, stml, flow,
                                          flowContext->captureFwd,
                                          flowContext->dpinum, rc);
        break;
    case 110:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessPOP3(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
    case 119:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessNNTP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
    case 143:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessIMAP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
    case 194:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessIRC(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
    case 427:

        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessSLP(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
    case 443:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessSSL(flowContext, rec, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
    case 554:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessRTSP(flowContext, stml, flow,
                                         flowContext->captureFwd,
                                         flowContext->dpinum, rc);
        break;
    case 5060:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessSIP(flowContext, stml, flow,
                                        flowContext->captureFwd,
                                        flowContext->dpinum, rc);
        break;
    case 3306:
        stml = fbSubTemplateMultiListGetNextEntry(rec, stml);
        flowContext->rec = ypProcessMySQL(flowContext, stml, flow,
                                          flowContext->captureFwd,
                                          flowContext->dpinum, rc);
        break;
    default:
        break;
    }

    /* For UNIFLOW -> we'll only get back to hooks if uniflow is set */
    /* This way we'll use flow->val.payload & offsets will still be correct */
    flowContext->startOffset = flowContext->captureFwd;
    flowContext->captureFwd = flowContext->dpinum;
    return TRUE;
}

/**
 * getInfoModel
 *
 * gets the IPFIX information model elements
 *
 *
 * @return a pointer to a fixbuf information element model array
 *
 */
fbInfoElement_t *ypGetInfoModel()
{
    return yaf_dpi_info_elements;
}

/**
 * getTemplate
 *
 * gets the IPFIX data template for the information that will be returned
 *
 * @return a pointer to the fixbuf info element array for the templates
 *
 */
gboolean ypGetTemplate(
    fbSession_t          *session)
{
    GError               *err = NULL;

    if (dpiInitialized == 0) {
        if (!ypHookInitialize(dpiRulesFileName, &err)) {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(194)) {
        if (!(ircTemplate = ypInitTemplate(session, yaf_singleBL_spec,
                                           YAF_IRC_FLOW_TID, 0xffffffff,
                                           &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(110)) {
        if (!(pop3Template = ypInitTemplate(session, yaf_singleBL_spec,
                                            YAF_POP3_FLOW_TID, 0xffffffff,
                                            &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(69)) {
        if (!(tftpTemplate = ypInitTemplate(session, yaf_tftp_spec,
                                            YAF_TFTP_FLOW_TID, 0xffffffff,
                                            &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(427)) {
        if (!(slpTemplate = ypInitTemplate(session, yaf_slp_spec,
                                           YAF_SLP_FLOW_TID, 0xffffffff,
                                           &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(80)) {
        if (!(httpTemplate = ypInitTemplate(session, yaf_http_spec,
                                            YAF_HTTP_FLOW_TID, 0xffffffff,
                                            &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(21)) {
        if (!(ftpTemplate = ypInitTemplate(session, yaf_ftp_spec,
                                           YAF_FTP_FLOW_TID, 0xffffffff,
                                           &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(143)) {
        if (!(imapTemplate = ypInitTemplate(session, yaf_imap_spec,
                                            YAF_IMAP_FLOW_TID, 0xffffffff,
                                            &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(554)) {
        if (!(rtspTemplate = ypInitTemplate(session, yaf_rtsp_spec,
                                            YAF_RTSP_FLOW_TID, 0xffffffff,
                                            &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(5060)) {
        if (!(sipTemplate = ypInitTemplate(session, yaf_sip_spec,
                                           YAF_SIP_FLOW_TID, 0xffffffff,
                                           &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(25)) {
        if (!(smtpTemplate = ypInitTemplate(session, yaf_smtp_spec,
                                            YAF_SMTP_FLOW_TID, 0xffffffff,
                                            &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(22)) {
        if (!(sshTemplate = ypInitTemplate(session, yaf_singleBL_spec,
                                           YAF_SSH_FLOW_TID, 0xffffffff,
                                           &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(119)) {
        if (!(nntpTemplate = ypInitTemplate(session, yaf_nntp_spec,
                                            YAF_NNTP_FLOW_TID, 0xffffffff,
                                            &err)))
        {
            return FALSE;
        }
    }

    if (ypSearchPlugOpts(53)) {
        if (!(dnsTemplate = ypInitTemplate(session, yaf_dns_spec,
                                           YAF_DNS_FLOW_TID, 0xffffffff,
                                           &err)))
        {
            return FALSE;
        }
        if (!(dnsQRTemplate = ypInitTemplate(session, yaf_dnsQR_spec,
                                             YAF_DNSQR_FLOW_TID, 0xffffffff,
                                             &err)))
        {
            return FALSE;
        }
        if (!(dnsATemplate = ypInitTemplate(session, yaf_dnsA_spec,
                                            YAF_DNSA_FLOW_TID, 0xffffffff,
                                            &err)))
        {
            return FALSE;
        }
        if (!(dnsAAAATemplate = ypInitTemplate(session, yaf_dnsAAAA_spec,
                                               YAF_DNSAAAA_FLOW_TID,
                                               0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(dnsCNTemplate = ypInitTemplate(session, yaf_dnsCNAME_spec,
                                             YAF_DNSCN_FLOW_TID, 0xffffffff,
                                             &err)))
        {
            return FALSE;
        }
        if (!(dnsMXTemplate = ypInitTemplate(session, yaf_dnsMX_spec,
                                             YAF_DNSMX_FLOW_TID, 0xffffffff,
                                             &err)))
        {
            return FALSE;
        }
        if (!(dnsNSTemplate = ypInitTemplate(session, yaf_dnsNS_spec,
                                             YAF_DNSNS_FLOW_TID, 0xffffffff,
                                             &err)))
        {
            return FALSE;
        }
        if (!(dnsPTRTemplate = ypInitTemplate(session, yaf_dnsPTR_spec,
                                              YAF_DNSPTR_FLOW_TID, 0xffffffff,
                                              &err)))
        {
            return FALSE;
        }
        if (!(dnsTXTTemplate = ypInitTemplate(session, yaf_dnsTXT_spec,
                                              YAF_DNSTXT_FLOW_TID, 0xffffffff,
                                              &err)))
        {
            return FALSE;
        }
        if (!(dnsSOATemplate = ypInitTemplate(session, yaf_dnsSOA_spec,
                                              YAF_DNSSOA_FLOW_TID, 0xffffffff,
                                              &err)))
        {
            return FALSE;
        }
        if (!(dnsSRVTemplate = ypInitTemplate(session, yaf_dnsSRV_spec,
                                              YAF_DNSSRV_FLOW_TID, 0xffffffff,
                                              &err)))
        {
            return FALSE;
        }
        if (dnssec) {
            if (!(dnsDSTemplate = ypInitTemplate(session, yaf_dnsDS_spec,
                                                 YAF_DNSDS_FLOW_TID,
                                                 0xffffffff,
                                                 &err)))
            {
                return FALSE;
            }
            if (!(dnsRRSigTemplate = ypInitTemplate(session, yaf_dnsSig_spec,
                                                    YAF_DNSRRSIG_FLOW_TID,
                                                    0xffffffff, &err)))
            {
                return FALSE;
            }
            if (!(dnsNSECTemplate = ypInitTemplate(session, yaf_dnsNSEC_spec,
                                                   YAF_DNSNSEC_FLOW_TID,
                                                   0xffffffff, &err)))
            {
                return FALSE;
            }
            if (!(dnsKeyTemplate = ypInitTemplate(session, yaf_dnsKey_spec,
                                                  YAF_DNSKEY_FLOW_TID,
                                                  0xffffffff, &err)))
            {
                return FALSE;
            }
            if (!(dnsNSEC3Template = ypInitTemplate(session, yaf_dnsNSEC3_spec,
                                                    YAF_DNSNSEC3_FLOW_TID,
                                                    0xffffffff, &err)))
            {
                return FALSE;
            }
        }
    }
    if (ypSearchPlugOpts(443)) {
        if (!(sslTemplate = ypInitTemplate(session, yaf_ssl_spec,
                                           YAF_SSL_FLOW_TID, 0xffffffff,
                                           &err)))
        {
            return FALSE;
        }
        if (!(sslCertTemplate = ypInitTemplate(session, yaf_cert_spec,
                                               YAF_SSL_CERT_FLOW_TID,
                                               0xffffffff, &err)))
        {
            return FALSE;
        }
        if (!(sslSubTemplate = ypInitTemplate(session, yaf_subssl_spec,
                                               YAF_SSL_SUBCERT_FLOW_TID,
                                               0xffffffff, &err)))
        {
            return FALSE;
        }

    }
    if (ypSearchPlugOpts(3306)) {
        if (!(mysqlTemplate = ypInitTemplate(session, yaf_mysql_spec,
                                             YAF_MYSQL_FLOW_TID, 0xffffffff,
                                             &err)))
        {
            return FALSE;
        }
        if (!(mysqlTxtTemplate = ypInitTemplate(session, yaf_mysql_txt_spec,
                                                YAF_MYSQLTXT_FLOW_TID,
                                                0xffffffff, &err)))
        {
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * setPluginOpt
 *
 * sets the pluginOpt variable passed from the command line
 *
 */
void ypSetPluginOpt(
    const char * option)
{
    ypProtocolHashInitialize();
    ypParsePluginOpt(option);
}

/**
 * setPluginConf
 *
 * sets the pluginConf variable passed from the command line
 *
 */
void ypSetPluginConf(
    char             *conf)
{
    if (NULL != conf) {
        dpiRulesFileName = conf;
    } else {
        dpiRulesFileName = YAF_CONF_DIR"/yafDPIRules.conf";
    }
}

/**
 * ypProtocolHashInitialize
 *
 */
void ypProtocolHashInitialize(
    )
{
    int               loop;
    uint16_t          insertLoc;

    for (loop = 0; loop < MAX_PAYLOAD_RULES; loop++) {
        dpiActiveHash[loop].activated = MAX_PAYLOAD_RULES + 1;
    }

    for (loop = 0; loop < DPI_TOTAL_PROTOCOLS; loop++) {
        insertLoc = DPIProtocols[loop] % MAX_PAYLOAD_RULES;
        if (dpiActiveHash[insertLoc].activated == (MAX_PAYLOAD_RULES + 1)) {
            dpiActiveHash[insertLoc].portNumber = DPIProtocols[loop];
            dpiActiveHash[insertLoc].activated = 0;
            dpiActiveHash[insertLoc].hash = 0;
        } else {
            insertLoc = ((MAX_PAYLOAD_RULES - DPIProtocols[loop]) ^
                         (DPIProtocols[loop] >> 8));
            insertLoc %= MAX_PAYLOAD_RULES;
            dpiActiveHash[insertLoc].portNumber = DPIProtocols[loop];
            dpiActiveHash[insertLoc].activated = 0;
            dpiActiveHash[insertLoc].hash = 0;
        }
    }

}

/**
 * ypProtocolHashSearch
 *
 */
uint16_t ypProtocolHashSearch(
    uint16_t                  portNum,
    uint16_t                  insert)
{
    uint16_t                  searchLoc = portNum % MAX_PAYLOAD_RULES;

    if (dpiActiveHash[searchLoc].portNumber == portNum) {
        if (insert) {
            dpiActiveHash[searchLoc].activated = insert;
        }
        return dpiActiveHash[searchLoc].activated;
    }

    searchLoc = ((MAX_PAYLOAD_RULES - portNum) ^ (portNum >> 8));
    searchLoc %= MAX_PAYLOAD_RULES;
    if (dpiActiveHash[searchLoc].portNumber == portNum) {
        if (insert) {
            dpiActiveHash[searchLoc].activated = insert;
        }
        return dpiActiveHash[searchLoc].activated;
    }

    return 0;
}

/**
 * ypProtocolHashActivate
 *
 */
gboolean ypProtocolHashActivate(
    uint16_t                    portNum,
    uint16_t                    index)
{
    if (!ypProtocolHashSearch(portNum, index)) {
        return FALSE;
    }

    return TRUE;
}



/**
 * ypParsePluginOpt
 *
 *  Parses pluginOpt string to find ports (applications) to execute
 *  Deep Packet Inspection
 *
 *  @param pluginOpt Variable
 *
 */
void ypParsePluginOpt(
    const char         *option)
{
    char               *plugOptIndex;
    char               *plugOpt, *endPlugOpt;
    int                dpiNumOn = 1;
    int                loop;

    plugOptIndex = (char *)option;
    while (NULL != plugOptIndex && (dpiNumOn < YAF_MAX_CAPTURE_FIELDS)) {
        endPlugOpt = strchr(plugOptIndex, ' ');
        if (endPlugOpt == NULL) {
            if (!(strcasecmp(plugOptIndex, "dnssec"))) {
                dnssec = TRUE;
                break;
            }
            if ( 0 == atoi(plugOptIndex)) {
                break;
            }
            if (!ypProtocolHashActivate((uint16_t)atoi(plugOptIndex),dpiNumOn))
            {
                g_debug("No Protocol %d for DPI", atoi(plugOptIndex));
                dpiNumOn--;
            }
            dpiNumOn++;
            break;
        } else if (plugOptIndex == endPlugOpt) {
            plugOpt = NULL;
            break;
        } else {
            plugOpt = g_new0(char, (endPlugOpt-plugOptIndex + 1));
            strncpy(plugOpt, plugOptIndex, (endPlugOpt - plugOptIndex));
            if (!(strcasecmp(plugOpt, "dnssec"))) {
                dnssec = TRUE;
                plugOptIndex = endPlugOpt + 1;
                continue;
            } else if (!ypProtocolHashActivate((uint16_t)atoi(plugOptIndex),
                                               dpiNumOn))
            {
                g_debug("No Protocol %d for DPI", atoi(plugOptIndex));
                dpiNumOn--;
            }
            dpiNumOn++;
        }
        plugOptIndex = endPlugOpt + 1;
    }

    if ((dpiNumOn > 1) && dnssec) {
        if (!ypProtocolHashSearch(53, 0)) {
            g_warning("DNSSEC NOT AVAILABLE - DNS DPI MUST ALSO BE ON");
            dnssec = FALSE;
        } else {
            g_debug("DPI Running for %d Protocols", dpiNumOn - 1);
            g_debug("DNSSEC export enabled.");
        }
    } else if (dnssec && dpiNumOn < 2) {
        g_debug("DPI Running for ALL Protocols");
        for (loop = 0; loop < DPI_TOTAL_PROTOCOLS; loop++) {
            ypProtocolHashActivate(DPIProtocols[loop], loop);
        }
        g_debug("DNSSEC export enabled.");
    } else {
        if (!option) {
            g_debug("DPI Running for ALL Protocols");
            for (loop = 0; loop < DPI_TOTAL_PROTOCOLS; loop++) {
                ypProtocolHashActivate(DPIProtocols[loop], loop);
            }
        } else {
            g_debug("DPI Running for %d Protocols", dpiNumOn - 1);
        }
    }

}


/**
 * scanPayload
 *
 * gets the important strings out of the payload by executing the passed pcre
 *
 *
 */

void ypScanPayload(
    void           *yfHookContext,
    yfFlow_t       *flow,
    const uint8_t  *pkt,
    size_t         caplen,
    pcre           *expression,
    uint16_t       offset,
    uint16_t       elementID,
    uint16_t       applabel)
{

    int            rc;
    int            vects[NUM_SUBSTRING_VECTS];
    unsigned int   captCount;
    ypDPIFlowCtx_t *flowContext = (ypDPIFlowCtx_t *)yfHookContext;

    if (NULL == flowContext) {
        return;
    }

    if (caplen == 0 && applabel != 53) {
        return;
    }

    /* determine if DPI is turned on for this appLabel */
    if (!ypSearchPlugOpts(applabel)) {
        return;
    }

    if (flowContext->dpi == NULL) {
        flowContext->dpi = yg_slice_alloc0(YAF_MAX_CAPTURE_FIELDS *
                                           sizeof(yfDPIData_t));
    }

    captCount = flowContext->dpinum;

    if ((expression == NULL) && (captCount < YAF_MAX_CAPTURE_FIELDS) &&
        (flowContext->dpi_len < dpi_user_total_limit))
    {
        if (caplen > dpi_user_limit) caplen = dpi_user_limit;
        flowContext->dpi[captCount].dpacketCaptLen = caplen;
        flowContext->dpi[captCount].dpacketID = elementID;
        flowContext->dpi[captCount].dpacketCapt = offset;
        flowContext->dpi_len += caplen;
        if (flowContext->dpi_len > dpi_user_total_limit) {
            /* if we passed the limit - don't add this one */
            return;
        }
        captCount++;
        flowContext->dpinum = captCount;
        return;
    }

    if (expression == NULL) {
        return;
    }

    rc = pcre_exec(expression, NULL, (char *)pkt, caplen, 0,
                   0, vects, NUM_SUBSTRING_VECTS);

    while ((rc > 0) && (captCount < YAF_MAX_CAPTURE_FIELDS) &&
           (flowContext->dpi_len < dpi_user_total_limit))
    {
        if (rc > 1) {
          flowContext->dpi[captCount].dpacketCaptLen = vects[3] - vects[2];
            flowContext->dpi[captCount].dpacketCapt = vects[2];
        } else {
          flowContext->dpi[captCount].dpacketCaptLen = vects[1] - vects[0];
            flowContext->dpi[captCount].dpacketCapt = vects[0];
        }

        if (flowContext->dpi[captCount].dpacketCaptLen <= 0) {
            flowContext->dpinum = captCount;
            return;
        }

        offset = vects[0] + flowContext->dpi[captCount].dpacketCaptLen;
        if (flowContext->dpi[captCount].dpacketCaptLen > dpi_user_limit) {
            flowContext->dpi[captCount].dpacketCaptLen = dpi_user_limit;
        }

        flowContext->dpi[captCount].dpacketID = elementID;
        flowContext->dpi_len += flowContext->dpi[captCount].dpacketCaptLen;

        if (flowContext->dpi_len > dpi_user_total_limit) {
            /* if we passed the limit - don't add this one */
            flowContext->dpinum = captCount;
            return;
        }
        captCount++;

        rc = pcre_exec(expression, NULL, (char *)(pkt), caplen, offset,
                       0, vects, NUM_SUBSTRING_VECTS);

    }

    flowContext->dpinum = captCount;
}


/**
 * ypGetMetaData
 *
 * this returns the meta information about this plugin, the interface version
 * it was built with, and the amount of export data it will send
 *
 * @return a pointer to a meta data structure with the various fields
 * appropriately filled in, API version & export data size
 *
 */
const struct yfHookMetaData* ypGetMetaData ()
{
    return &metaData;
}

/**
 * ypGetTemplateCount
 *
 * this returns the number of templates we are adding to yaf's
 * main subtemplatemultilist, for DPI - this is usually just 1
 *
 */
uint8_t ypGetTemplateCount(
    void                   *yfHookContext,
    yfFlow_t               *flow)
{

    ypDPIFlowCtx_t         *flowContext = (ypDPIFlowCtx_t *)yfHookContext;

    if (NULL == flowContext) {
        return 0;
    }

    if (!flowContext->dpinum) {
        /* Nothing captured */
        return 0;
    }

    if (!ypSearchPlugOpts(flow->appLabel)) {
        return 0;
    }

    /* if this is uniflow & there's no rval DPI - then it will return 0 */
    if (!flow->rval.payload && !flowContext->captureFwd) {
        return 0;
    }

    /* if this is not uniflow startOffset should be 0 */
    if ((flowContext->startOffset < flowContext->dpinum))
    {
        return 1;
    } else {
        /* won't pass condition to free */
        flowContext->startOffset = flowContext->dpinum + 1;
        return 0;
    }

}

/**
 * ypFreeLists
 *
 *
 *
 *
 */
void ypFreeLists(
    void             *yfHookContext,
    yfFlow_t         *flow)
{

    ypDPIFlowCtx_t   *flowContext = (ypDPIFlowCtx_t *)yfHookContext;

    if (NULL == flowContext) {
        /* log an error here, but how */
        g_warning("couldn't free flow %p; not in hash table\n", flow);
        return;
    }

    if (!flowContext->dpinum) {
        return;
    }

    if (!ypSearchPlugOpts(flow->appLabel)) {
        return;
    }

    if (!flowContext->startOffset && !flow->rval.payload) {
  /* Uniflow case: captures must be in rev payload but we don't have it now */
        /* Biflow case: startOffset is 0 and fwdcap is 0, we did get something
           and its in the rev payload */
        return;
    }

    if (flowContext->startOffset <= flowContext->dpinum) {
        switch (flow->appLabel) {
        case 80:
            ypFreeHTTPRec(flowContext);
            break;
        case 443:
            ypFreeSSLRec(flowContext);
            break;
        case 21:
            ypFreeFTPRec(flowContext);
            break;
        case 53:
            ypFreeDNSRec(flowContext);
            break;
        case 25:
            ypFreeSMTPRec(flowContext);
            break;
        case 22:
            ypFreeSSHRec(flowContext);
            break;
        case 143:
            ypFreeIMAPRec(flowContext);
            break;
        case 69:
            ypFreeTFTPRec(flowContext);
            break;
        case 110:
            ypFreePOP3Rec(flowContext);
            break;
        case 119:
            ypFreeNNTPRec(flowContext);
            break;
        case 194:
            ypFreeIRCRec(flowContext);
            break;
        case 427:
            ypFreeSLPRec(flowContext);
            break;
        case 554:
            ypFreeRTSPRec(flowContext);
            break;
        case 5060:
            ypFreeSIPRec(flowContext);
            break;
        case 3306:
            ypFreeMySQLRec(flowContext);
            break;
        default:
            break;
        }

        if (flowContext->exbuf) {
            yg_slice_free1(dpi_user_total_limit, flowContext->exbuf);
        }
    }

    return;
}

uint8_t
ypDPIScanner (
    ypDPIFlowCtx_t     *flowContext,
    const uint8_t      *payloadData,
    unsigned int       payloadSize,
    yfFlow_t           *flow,
    yfFlowVal_t        *val)
{

    int                rc = 0;
    int                loop;
    int                subVects[NUM_SUBSTRING_VECTS];
    uint16_t           offsetptr;
    uint8_t            captCount = flowContext->dpinum;
    uint8_t            newCapture = flowContext->dpinum;
    uint8_t            captDirection = 0;
    uint16_t           captLen = 0;
    pcre               *ruleHolder;
    pcre_extra         *extraHolder;
    int                rulePos = 0;

    rulePos = ypProtocolHashSearch(flow->appLabel, 0);
    if (!rulePos) {
        return 0;
    }

    for ( loop = 0; loop < ruleSet[rulePos].numRules; loop++) {
        ruleHolder = ruleSet[rulePos].regexFields[loop].rule;
        extraHolder = ruleSet[rulePos].regexFields[loop].extra;
        offsetptr = 0;
        rc = pcre_exec(ruleHolder, extraHolder,
                       (char *)payloadData, payloadSize, 0,
                       0, subVects, NUM_SUBSTRING_VECTS) ;

        while ( (rc > 0) && (captDirection < YAF_MAX_CAPTURE_SIDE)) {
            /*Get only matched substring - don't need Labels*/
            if (rc > 1) {
                captLen = subVects[3] - subVects[2];
                flowContext->dpi[captCount].dpacketCapt = subVects[2];
            } else {
                captLen = subVects[1] - subVects[0];
                flowContext->dpi[captCount].dpacketCapt = subVects[0];
            }

            if (captLen <= 0) {
                flowContext->dpinum = captCount;
                return (flowContext->dpinum - newCapture);
            }

            /* truncate capture length to capture limit */
            flowContext->dpi[captCount].dpacketID =
                ruleSet[rulePos].regexFields[loop].info_element_id;
            if (captLen > dpi_user_limit) captLen = dpi_user_limit;
            flowContext->dpi[captCount].dpacketCaptLen =  captLen;
            flowContext->dpi_len += captLen;
            if (flowContext->dpi_len > dpi_user_total_limit) {
                /* buffer full */
                flowContext->dpinum = captCount;
                return captDirection;
            }
            offsetptr = subVects[0] + captLen;
            captCount++;
            captDirection++;
            rc = pcre_exec(ruleHolder, extraHolder, (char *)(payloadData),
                           payloadSize, offsetptr, 0, subVects,
                           NUM_SUBSTRING_VECTS);
        }
    }

    flowContext->dpinum = captCount;

    return captDirection;
}


/**
 * Protocol Specific Functions
 *
 */

fbTemplate_t * ypInitTemplate(
    fbSession_t *session,
    fbInfoElementSpec_t *spec,
    uint16_t tid,
    uint32_t flags,
    GError **err)
{
    fbInfoModel_t *model = ypGetDPIInfoModel();
    fbTemplate_t *tmpl = NULL;
    gboolean rc = TRUE;
    GError *error = NULL;

    tmpl = fbTemplateAlloc(model);
    if (!fbTemplateAppendSpecArray(tmpl, spec, flags, &error)) {
        g_debug("Error adding spec array to template for tid %d %s", tid,
                error->message);
        return NULL;
    }

    if (tid == YAF_HTTP_FLOW_TID) {
        if (yaf_http_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_http_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_IMAP_FLOW_TID) {
        if (yaf_imap_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_imap_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_FTP_FLOW_TID) {
        if (yaf_ftp_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_ftp_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_RTSP_FLOW_TID) {
        if (yaf_rtsp_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_rtsp_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_SSH_FLOW_TID) {
        if (yaf_ssh_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_ssh_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_SIP_FLOW_TID) {
        if (yaf_sip_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_sip_extra, 0xffffffff,
                                           &error);
        }
    } else if (tid == YAF_SMTP_FLOW_TID) {
        if (yaf_smtp_extra) {
            rc = fbTemplateAppendSpecArray(tmpl, yaf_smtp_extra, 0xffffffff,
                                           &error);
        }
    }

    if (!rc) {
        g_debug("Error adding extra spec array to template with tid %02x: %s",
                tid, error->message);
        return NULL;
    }

    if (!fbSessionAddTemplate(session, FALSE, tid, tmpl, &error)) {
        g_debug("Error adding template %02x: %s", tid, error->message);
        return NULL;
    }

    return tmpl;
}

void *ypProcessIRC(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    fbVarfield_t *ircVarfield;
    yfIRCFlow_t  *rec = (yfIRCFlow_t *)flowContext->rec;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    int count = flowContext->startOffset;

    rec =(yfIRCFlow_t *)fbSubTemplateMultiListEntryInit(stml, YAF_IRC_FLOW_TID,
                                                        ircTemplate, 1);

    ircVarfield = (fbVarfield_t *)fbBasicListInit(&(rec->ircMsg), 0,
                  fbInfoModelGetElementByName(model, "ircTextMessage"),
                                                  totalcap);

    while (count < fwdcap) {
        ircVarfield->buf = flow->val.payload + dpi[count].dpacketCapt;
        ircVarfield->len = dpi[count].dpacketCaptLen;
        ircVarfield++;
        count++;
    }

    if (fwdcap < totalcap && flow->rval.payload) {
        while (count < totalcap) {
            ircVarfield->buf = flow->rval.payload + dpi[count].dpacketCapt;
            ircVarfield->len = dpi[count].dpacketCaptLen;
            ircVarfield++;
            count++;
        }
    }

    return (void *)rec;
}

void *ypProcessPOP3(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t  *dpi = flowContext->dpi;
    fbVarfield_t *popvar;
    yfPOP3Flow_t *rec = (yfPOP3Flow_t *)flowContext->rec;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    int count = flowContext->startOffset;

    rec = (yfPOP3Flow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_POP3_FLOW_TID,
                                                          pop3Template, 1);
    popvar = (fbVarfield_t *)fbBasicListInit(&(rec->pop3msg), 0,
                     fbInfoModelGetElementByName(model, "pop3TextMessage"),
                                             totalcap);

    while (count < fwdcap && popvar) {
        popvar->buf = flow->val.payload + dpi[count].dpacketCapt;
        popvar->len = dpi[count].dpacketCaptLen;
        popvar = fbBasicListGetNextPtr(&(rec->pop3msg), popvar);
        count++;

    }

    if (fwdcap < totalcap && flow->rval.payload) {
        while (count < totalcap && popvar) {
            popvar->buf = flow->rval.payload + dpi[count].dpacketCapt;
            popvar->len = dpi[count].dpacketCaptLen;
            popvar = fbBasicListGetNextPtr(&(rec->pop3msg), popvar);
            count++;
        }
    }

    return (void *)rec;
}

void *ypProcessTFTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfTFTPFlow_t *rec = (yfTFTPFlow_t *)flowContext->rec;
    int count = flowContext->startOffset;

    rec = (yfTFTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_TFTP_FLOW_TID,
                                                          tftpTemplate, 1);

    if (fwdcap) {
        rec->tftpFilename.buf = flow->val.payload + dpi[count].dpacketCapt;
        rec->tftpFilename.len = dpi[count].dpacketCaptLen;
        if (fwdcap > 1) {
            count++;
            rec->tftpMode.buf = flow->val.payload + dpi[count].dpacketCapt;
            rec->tftpMode.len = dpi[count].dpacketCaptLen;
        }
    } else if (flow->rval.payload) {
        rec->tftpFilename.buf = flow->rval.payload + dpi[count].dpacketCapt;
        rec->tftpFilename.len = dpi[count].dpacketCaptLen;
        if (dpi[++count].dpacketCapt) {
            rec->tftpMode.buf = flow->rval.payload + dpi[count].dpacketCapt;
            rec->tftpMode.len = dpi[count].dpacketCaptLen;
        }
    }

    return (void *)rec;
}

void *ypProcessSLP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfSLPFlow_t *rec = (yfSLPFlow_t *)flowContext->rec;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    int loop;
    int total = 0;
    int count = flowContext->startOffset;
    fbVarfield_t *slpVar = NULL;

    rec = (yfSLPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                         YAF_SLP_FLOW_TID,
                                                         slpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    for (loop = count; loop < totalcap; loop++) {
        if (dpi[loop].dpacketID > 91) {
            total++;
        }
    }
    slpVar = (fbVarfield_t *)fbBasicListInit(&(rec->slpString), 0,
                       fbInfoModelGetElementByName(model, "slpString"), total);

    while (count < fwdcap) {
        if (dpi[count].dpacketID == 90) {
            rec->slpVersion = (uint8_t)*(flow->val.payload +
                                         dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID == 91) {
            rec->slpMessageType = (uint8_t)*(flow->val.payload +
                                             dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID > 91 && slpVar) {
            slpVar->buf = flow->val.payload + dpi[count].dpacketCapt;
            slpVar->len = dpi[count].dpacketCaptLen;
            slpVar = fbBasicListGetNextPtr(&(rec->slpString), slpVar);
        }
        count++;
    }

    /* should we collect reverse SLP version and message Type? */
    while (count < totalcap && flow->rval.payload) {
        if (dpi[count].dpacketID == 90) {
            rec->slpVersion = (uint8_t)*(flow->rval.payload +
                                         dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID == 91) {
          rec->slpMessageType = (uint8_t)*(flow->rval.payload +
                                           dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID > 91 && slpVar) {
            slpVar->buf= flow->rval.payload + dpi[count].dpacketCapt;
            slpVar->len= dpi[count].dpacketCaptLen;
            slpVar = fbBasicListGetNextPtr(&(rec->slpString), slpVar);
        }
        count++;
    }

    return (void *)rec;
}

void *ypProcessHTTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfHTTPFlow_t *rec = (yfHTTPFlow_t *)flowContext->rec;
    fbVarfield_t *httpVar = NULL;
    uint8_t start = flowContext->startOffset;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];
    uint16_t total = 0;
    uint16_t temp_element;
    int loop, oloop;
    ypBLValue_t *val;
    fbBasicList_t *blist = NULL;

    rec = (yfHTTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_HTTP_FLOW_TID,
                                                          httpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    if (!dpiActiveHash[rulePos].hash) {
        ypAddHTTPRules(flowContext);
        dpiActiveHash[rulePos].hash = 1;
    }

    ypInitializeHTTPBL(&rec);

    for (oloop = 0; oloop < ruleSet[rulePos].numRules; oloop++) {
        temp_element = ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(80, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                httpVar = (fbVarfield_t *)fbBasicListInit(blist, 0,
                                                          val->infoElement,
                                                          total);
                ypFillBasicList(flow, dpi, total, fwdcap,&httpVar, totalIndex);
            }
            total = 0;
            httpVar = NULL;
        }
    }

    return (void *)rec;
}

void *ypProcessFTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t *dpi = flowContext->dpi;
    yfFTPFlow_t *rec = (yfFTPFlow_t *)flowContext->rec;
    fbVarfield_t *ftpVar = NULL;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];
    uint8_t start = flowContext->startOffset;
    uint16_t temp_element;
    int loop, oloop;
    ypBLValue_t *val;
    int total = 0;
    fbBasicList_t *blist;


    rec = (yfFTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_FTP_FLOW_TID,
                                                          ftpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }


    if (!dpiActiveHash[rulePos].hash) {
        ypAddFTPRules(flowContext);
        dpiActiveHash[rulePos].hash = 1;
    }

    ypInitializeFTPBL(&rec);

    for (oloop = 0; oloop < ruleSet[rulePos].numRules; oloop++) {
        temp_element = ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(21, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                ftpVar = (fbVarfield_t *)fbBasicListInit(blist, 0,
                                                         val->infoElement,
                                                         total);
                ypFillBasicList(flow, dpi, total, fwdcap, &ftpVar, totalIndex);
            }
            total = 0;
            ftpVar = NULL;
        }
    }

    return (void *)rec;
}

void *ypProcessIMAP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfIMAPFlow_t *rec = (yfIMAPFlow_t *)flowContext->rec;
    uint8_t start = flowContext->startOffset;
    fbVarfield_t *imapVar = NULL;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];
    uint16_t temp_element;
    int loop, oloop;
    fbBasicList_t *blist;
    ypBLValue_t *val;
    int total = 0;

    rec = (yfIMAPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_IMAP_FLOW_TID,
                                                          imapTemplate, 1);

    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    if (!dpiActiveHash[rulePos].hash) {
        ypAddIMAPRules(flowContext);
        dpiActiveHash[rulePos].hash = 1;
    }

    ypInitializeIMAPBL(&rec);

    for (oloop = 0; oloop < ruleSet[rulePos].numRules; oloop++) {
        temp_element = ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(143, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                imapVar = (fbVarfield_t *)fbBasicListInit(blist, 0,
                                                         val->infoElement,
                                                         total);
                ypFillBasicList(flow, dpi, total, fwdcap,&imapVar, totalIndex);
            }
            total = 0;
            imapVar = NULL;
        }
    }

    return (void *)rec;
}

void *ypProcessSIP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t *dpi = flowContext->dpi;
    yfSIPFlow_t *rec = (yfSIPFlow_t *)flowContext->rec;
    uint8_t start = flowContext->startOffset;
    int total = 0;
    fbVarfield_t *sipVar = NULL;
    uint16_t temp_element;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];
    int loop, oloop;
    fbBasicList_t *blist;
    ypBLValue_t *val;

    rec = (yfSIPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                         YAF_SIP_FLOW_TID,
                                                         sipTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    if (!dpiActiveHash[rulePos].hash) {
        ypAddSIPRules(flowContext);
        dpiActiveHash[rulePos].hash = 1;
    }

    ypInitializeSIPBL(&rec);

    for (oloop = 0; oloop < ruleSet[rulePos].numRules; oloop++) {
        temp_element = ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(5060, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                sipVar = (fbVarfield_t *)fbBasicListInit(blist, 0,
                                                         val->infoElement,
                                                         total);
                ypFillBasicList(flow, dpi, total, fwdcap, &sipVar, totalIndex);
            }
            total = 0;
            sipVar = NULL;
        }
    }

    return (void *)rec;
}

void *ypProcessSMTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfSMTPFlow_t *rec = (yfSMTPFlow_t *)flowContext->rec;
    uint8_t start = flowContext->startOffset;
    int total = 0;
    fbVarfield_t *smtpVar = NULL;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];
    uint16_t temp_element;
    int loop, oloop;
    fbBasicList_t *blist;
    ypBLValue_t *val
;
    rec = (yfSMTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_SMTP_FLOW_TID,
                                                          smtpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    if (!dpiActiveHash[rulePos].hash) {
        ypAddSMTPRules(flowContext);
        dpiActiveHash[rulePos].hash = 1;
    }

    ypInitializeSMTPBL(&rec);

    for (oloop = 0; oloop < ruleSet[rulePos].numRules; oloop++) {
        temp_element = ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }

        if (total) {
            val = ypGetRule(25, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                smtpVar = (fbVarfield_t *)fbBasicListInit(blist, 0,
                                                         val->infoElement,
                                                         total);
                ypFillBasicList(flow, dpi, total,fwdcap, &smtpVar, totalIndex);
            }
            total = 0;
            smtpVar = NULL;
        }
    }

    return (void *)rec;
}

void *ypProcessNNTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfNNTPFlow_t *rec = (yfNNTPFlow_t *)flowContext->rec;
    fbInfoModel_t *model = ypGetDPIInfoModel();
    uint8_t count;
    uint8_t start = flowContext->startOffset;
    int total = 0;
    fbVarfield_t *nntpVar = NULL;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];

    rec = (yfNNTPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_NNTP_FLOW_TID,
                                                          nntpTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    /* nntp Response */
    for (count = start; count < totalcap; count++) {
        if (dpi[count].dpacketID == 172) {
            totalIndex[total] = count;
            total++;
        }
    }

    nntpVar = (fbVarfield_t *)fbBasicListInit(&(rec->nntpResponse), 0,
                           fbInfoModelGetElementByName(model, "nntpResponse"),
                                              total);

    ypFillBasicList(flow, dpi, total, fwdcap, &nntpVar, totalIndex);

    total = 0;
    nntpVar = NULL;
    /* nntp Command */
    for (count = start; count < totalcap; count++) {
        if (dpi[count].dpacketID == 173) {
            totalIndex[total] = count;
            total++;
        }
    }

    nntpVar = (fbVarfield_t *)fbBasicListInit(&(rec->nntpCommand), 0,
                            fbInfoModelGetElementByName(model, "nntpCommand"),
                                              total);

    ypFillBasicList(flow, dpi, total, fwdcap, &nntpVar, totalIndex);

    return (void *)rec;
}

void *ypProcessSSL(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiList_t      *mainRec,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t         *dpi = flowContext->dpi;
    yfSSLFlow_t         *rec = (yfSSLFlow_t *)flowContext->rec;
    yfSSLCertFlow_t     *sslcert = NULL;
    fbInfoModel_t       *model = ypGetDPIInfoModel();
    int                 count = flowContext->startOffset;
    int                 total_certs = 0;
    uint32_t            *sslCiphers;
    uint8_t             *payload = NULL;
    size_t              paySize = 0;
    uint8_t             totalIndex[YAF_MAX_CAPTURE_FIELDS];
    gboolean            ciphertrue = FALSE;
    int                 i;

    rec =(yfSSLFlow_t *)fbSubTemplateMultiListEntryInit(stml, YAF_SSL_FLOW_TID,
                                                        sslTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    while (count < totalcap) {
        if (count < fwdcap) {
            payload = flow->val.payload;
            paySize = flow->val.paylen;
        } else if (flow->rval.payload) {
            payload = flow->rval.payload;
            paySize = flow->rval.paylen;
        } else {
            continue;
        }

        if (dpi[count].dpacketID == 91) {
            sslCiphers = (uint32_t *)fbBasicListInit(&(rec->sslCipherList), 0,
                               fbInfoModelGetElementByName(model, "sslCipher"),
                                                 dpi[count].dpacketCaptLen/2);
            for (i=0; i < (dpi[count].dpacketCaptLen/2); i++) {
                *sslCiphers = (uint32_t)ntohs(*(uint16_t *)(payload +
                                                      dpi[count].dpacketCapt +
                                                            (i * 2)));
                if (!(sslCiphers = fbBasicListGetNextPtr(&(rec->sslCipherList),
                                                         sslCiphers)))
                {
                    break;
                }
            }
            ciphertrue = TRUE;
        } else if (dpi[count].dpacketID == 90) {
            rec->sslCompressionMethod = *(payload + dpi[count].dpacketCapt);
        } else if (dpi[count].dpacketID == 88) {
            rec->sslClientVersion = dpi[count].dpacketCapt;
            if (rec->sslClientVersion != 2 && rec->sslClientVersion!= 3) {
            }
        } else if (dpi[count].dpacketID == 89) {
            rec->sslServerCipher = ntohs(*(uint16_t *)(payload +
                                                      dpi[count].dpacketCapt));
        } else if (dpi[count].dpacketID == 92) {
            sslCiphers = (uint32_t *)fbBasicListInit(&(rec->sslCipherList), 0,
                               fbInfoModelGetElementByName(model, "sslCipher"),
                                                  dpi[count].dpacketCaptLen/3);
            for (i=0; i < (dpi[count].dpacketCaptLen/3); i++) {
                *sslCiphers =(ntohl(*(uint32_t *)(payload +
                                                  dpi[count].dpacketCapt +
                                                  (i * 3))) & 0xFFFFFF00) >> 8;
                if (!(sslCiphers = fbBasicListGetNextPtr(&(rec->sslCipherList),
                                                         sslCiphers)))
                {
                    break;
                }
            }
            ciphertrue = TRUE;
        } else if (dpi[count].dpacketID == 93) {
            totalIndex[total_certs] = count;
            total_certs++;
        }

        count++;
    }

    if (!ciphertrue) {
        fbBasicListInit(&(rec->sslCipherList), 0,
                        fbInfoModelGetElementByName(model, "sslCipher"), 0);
    }
    sslcert = (yfSSLCertFlow_t *)fbSubTemplateListInit(&(rec->sslCertList), 0,
                                                       YAF_SSL_CERT_FLOW_TID,
                                                       sslCertTemplate,
                                                       total_certs);

    for (i = 0; i < total_certs; i++) {
        if (totalIndex[i] < fwdcap) {
            payload = flow->val.payload;
            paySize = flow->val.paylen;
        } else if (flow->rval.payload) {
            payload = flow->rval.payload;
            paySize = flow->rval.paylen;
        }
        if (!ypDecodeSSLCertificate(&sslcert, payload, paySize, flow,
                                    dpi[totalIndex[i]].dpacketCapt)) {
            if (sslcert->issuer.tmpl == NULL) {
                fbSubTemplateListInit(&(sslcert->issuer), 0,
                                      YAF_SSL_SUBCERT_FLOW_TID,
                                      sslSubTemplate, 0);
            }
            if (sslcert->subject.tmpl == NULL) {
                fbSubTemplateListInit(&(sslcert->subject), 0,
                                      YAF_SSL_SUBCERT_FLOW_TID,
                                      sslSubTemplate, 0);
            }
            if (sslcert->extension.tmpl == NULL) {
                fbSubTemplateListInit(&(sslcert->extension), 0,
                                      YAF_SSL_SUBCERT_FLOW_TID,
                                      sslSubTemplate, 0);
            }
        }

        if (!(sslcert =
              fbSubTemplateListGetNextPtr(&(rec->sslCertList), sslcert)))
        {
            break;
        }
    }

    return (void *)rec;
}


void *ypProcessSSH(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t *dpi = flowContext->dpi;
    yfSSHFlow_t *rec = (yfSSHFlow_t *)flowContext->rec;
    int start = flowContext->startOffset;
    fbVarfield_t *sshVar = NULL;
    fbBasicList_t *blist = NULL;
    ypBLValue_t *val;
    uint16_t temp_element;
    int loop, oloop;
    uint16_t total = 0;
    uint8_t totalIndex[YAF_MAX_CAPTURE_FIELDS];

    rec = (yfSSHFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                         YAF_SSH_FLOW_TID,
                                                         sshTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    if (!dpiActiveHash[rulePos].hash) {
        ypAddSSHRules(flowContext);
        dpiActiveHash[rulePos].hash = 1;
    }

    ypInitializeSSHBL(&rec);

    for (oloop = 0; oloop < ruleSet[rulePos].numRules; oloop++) {
        temp_element = ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(22, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                sshVar = (fbVarfield_t *)fbBasicListInit(blist, 0,
                                                         val->infoElement,
                                                         total);
                ypFillBasicList(flow, dpi, total, fwdcap, &sshVar, totalIndex);
            }
            total = 0;
            sshVar = NULL;
        }
    }
    return (void *)rec;
}

void *ypProcessDNS(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{
    yfDPIData_t                   *dpi = flowContext->dpi;
    yfDNSFlow_t                   *rec = (yfDNSFlow_t *)flowContext->rec;
    yfDNSQRFlow_t                 *dnsQRecord = NULL;
    uint8_t                       recCountFwd = 0;
    uint8_t                       recCountRev = 0;
    unsigned int                  buflen = 0;
    int                           count = flowContext->startOffset;

    flowContext->exbuf = yg_slice_alloc0(dpi_user_total_limit);

    rec = (yfDNSFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                         YAF_DNS_FLOW_TID,
                                                         dnsTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    while (count < totalcap) {
        if (dpi[count].dpacketID == 0) {
            recCountFwd += dpi[count].dpacketCapt;
        }
        if (dpi[count].dpacketID == 1) {
            recCountRev += dpi[count].dpacketCapt;
        }
        count++;
    }

    dnsQRecord = (yfDNSQRFlow_t *)fbSubTemplateListInit(&(rec->dnsQRList), 0,
                                                        YAF_DNSQR_FLOW_TID,
                                                        dnsQRTemplate,
                                                        recCountFwd +
                                                        recCountRev);
    if (!dnsQRecord) {
        g_debug("Error initializing SubTemplateList for DNS Resource "
                "Record with %d Templates", recCountFwd + recCountRev);
        return NULL;
    }

    if (flow->val.payload && recCountFwd) {
        ypDNSParser(&dnsQRecord, flow->val.payload, flow->val.paylen,
                    flowContext->exbuf, &buflen, recCountFwd);
    }

    if (recCountRev) {
        if (recCountFwd) {
            if (!(dnsQRecord = fbSubTemplateListGetNextPtr(&(rec->dnsQRList),
                                                           dnsQRecord)))
            {
                return (void *)rec;
            }
        }
        if (!flow->rval.payload) {
            /* Uniflow */
            ypDNSParser(&dnsQRecord, flow->val.payload, flow->val.paylen,
                        flowContext->exbuf, &buflen, recCountRev);
        } else {
            ypDNSParser(&dnsQRecord, flow->rval.payload, flow->rval.paylen,
                        flowContext->exbuf, &buflen, recCountRev);
        }
    }

    return (void *)rec;
}


void *ypProcessRTSP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{

    yfDPIData_t                  *dpi = flowContext->dpi;
    yfRTSPFlow_t                 *rec = (yfRTSPFlow_t *)flowContext->rec;
    fbVarfield_t                 *rtspVar = NULL;
    fbBasicList_t                *blist;
    ypBLValue_t                  *val;
    uint8_t                      start = flowContext->startOffset;
    int                          total = 0;
    uint8_t                      totalIndex[YAF_MAX_CAPTURE_FIELDS];
    uint16_t                     temp_element;
    int                          loop, oloop;


    rec = (yfRTSPFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_RTSP_FLOW_TID,
                                                          rtspTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    if (!dpiActiveHash[rulePos].hash) {
        ypAddRTSPRules(flowContext);
        dpiActiveHash[rulePos].hash = 1;
    }

    ypInitializeRTSPBL(&rec);

    for (oloop = 0; oloop < ruleSet[rulePos].numRules; oloop++) {
        temp_element = ruleSet[rulePos].regexFields[oloop].info_element_id;
        for (loop = start; loop < totalcap; loop++) {
            if (flowContext->dpi[loop].dpacketID == temp_element) {
                totalIndex[total] = loop;
                total++;
            }
        }
        if (total) {
            val = ypGetRule(554, temp_element);
            if (val) {
                char *sc = (char *)rec;
                blist = (fbBasicList_t *)(sc + val->BLoffset);
                rtspVar = (fbVarfield_t *)fbBasicListInit(blist, 0,
                                                          val->infoElement,
                                                          total);
                ypFillBasicList(flow, dpi, total, fwdcap,&rtspVar, totalIndex);
            }
            total = 0;
            rtspVar = NULL;
        }
    }
    return (void *)rec;
}

void *ypProcessMySQL(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos)
{


    yfDPIData_t                  *dpi = flowContext->dpi;
    yfMySQLFlow_t                *rec = (yfMySQLFlow_t *)flowContext->rec;
    yfMySQLTxtFlow_t             *mysql = NULL;
    uint8_t                      count;
    uint8_t                      start = flowContext->startOffset;
    int                          total = 0;

    rec = (yfMySQLFlow_t *)fbSubTemplateMultiListEntryInit(stml,
                                                          YAF_MYSQL_FLOW_TID,
                                                          mysqlTemplate, 1);
    if (!flow->rval.payload) {
        totalcap = fwdcap;
    }

    count = start;
    while (count < totalcap) {
        if ((dpi[count].dpacketID != 223) && (dpi[count].dpacketID < 0x1d)) {
            total++;
        }
        count++;
    }

    mysql = (yfMySQLTxtFlow_t *)fbSubTemplateListInit(&(rec->mysqlList), 0,
                                                      YAF_MYSQLTXT_FLOW_TID,
                                                      mysqlTxtTemplate,
                                                      total);
    count = start;
    while (count < fwdcap && mysql) {
        /* MySQL Username */
        if (dpi[count].dpacketID == 223) {
            rec->mysqlUsername.buf = flow->val.payload +dpi[count].dpacketCapt;
            rec->mysqlUsername.len = dpi[count].dpacketCaptLen;
        } else {
            mysql->mysqlCommandCode = dpi[count].dpacketID;
            mysql->mysqlCommandText.buf = flow->val.payload +
                                          dpi[count].dpacketCapt;
            mysql->mysqlCommandText.len = dpi[count].dpacketCaptLen;
            mysql = fbSubTemplateListGetNextPtr(&(rec->mysqlList), mysql);
        }
        count++;
    }

    while (count < totalcap && mysql && flow->rval.payload) {
        /* MySQL Username */
        if (dpi[count].dpacketID == 223) {
            rec->mysqlUsername.buf =flow->rval.payload +dpi[count].dpacketCapt;
            rec->mysqlUsername.len = dpi[count].dpacketCaptLen;
        } else {
            mysql->mysqlCommandCode = dpi[count].dpacketID;
            mysql->mysqlCommandText.buf = flow->rval.payload +
                                          dpi[count].dpacketCapt;
            mysql->mysqlCommandText.len= dpi[count].dpacketCaptLen;
            mysql = fbSubTemplateListGetNextPtr(&(rec->mysqlList), mysql);
        }
        count++;
    }

    return (void *)rec;
}

void ypFillBasicList(
    yfFlow_t         *flow,
    yfDPIData_t      *dpi,
    uint8_t          totalCaptures,
    uint8_t          forwardCaptures,
    fbVarfield_t     **varField,
    uint8_t          *indexArray)
{
    int i;

    if (!(*varField)) {
        return;
    }

    for (i = 0; i < totalCaptures; i++) {
        if (indexArray[i] < forwardCaptures) {
            if ((dpi[indexArray[i]].dpacketCapt +
                 dpi[indexArray[i]].dpacketCaptLen) > flow->val.paylen) {
                continue;
            }
            if (flow->val.payload) {
                (*varField)->buf = flow->val.payload +
                    dpi[indexArray[i]].dpacketCapt;
                (*varField)->len = dpi[indexArray[i]].dpacketCaptLen;
            }
        } else {
            if ((dpi[indexArray[i]].dpacketCapt +
                 dpi[indexArray[i]].dpacketCaptLen) > flow->rval.paylen) {
                continue;
            }
            if (flow->rval.payload) {
                (*varField)->buf = flow->rval.payload +
                    dpi[indexArray[i]].dpacketCapt;
                (*varField)->len = dpi[indexArray[i]].dpacketCaptLen;
            }
        }

        if (i + 1 < totalCaptures) {
            (*varField)++;
        }
    }

}

void ypFreeHTTPRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfHTTPFlow_t *rec = (yfHTTPFlow_t *)flowContext->rec;
    fbBasicList_t *temp = (fbBasicList_t *)rec->httpBasicListBuf;
    int loop, rc;
    size_t offset;

    fbBasicListClear(&(rec->server));
    fbBasicListClear(&(rec->userAgent));
    fbBasicListClear(&(rec->get));
    fbBasicListClear(&(rec->connection));
    fbBasicListClear(&(rec->referer));
    fbBasicListClear(&(rec->location));
    fbBasicListClear(&(rec->host));
    fbBasicListClear(&(rec->contentLength));
    fbBasicListClear(&(rec->age));
    fbBasicListClear(&(rec->response));
    fbBasicListClear(&(rec->acceptLang));
    fbBasicListClear(&(rec->accept));
    fbBasicListClear(&(rec->contentType));
    fbBasicListClear(&(rec->httpVersion));
    fbBasicListClear(&(rec->httpCookie));
    fbBasicListClear(&(rec->httpSetCookie));

    rc = ypAddSpec(NULL, 80, &offset);
    /* Free any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListClear(temp);
        temp++;
    }


}

void ypFreeSLPRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfSLPFlow_t *rec = (yfSLPFlow_t *)flowContext->rec;

    fbBasicListClear(&(rec->slpString));

}

void ypFreeIRCRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfIRCFlow_t *rec = (yfIRCFlow_t *)flowContext->rec;
    fbBasicListClear(&(rec->ircMsg));

}

void ypFreePOP3Rec(
    ypDPIFlowCtx_t *flowContext)
{

    yfPOP3Flow_t *rec = (yfPOP3Flow_t *)flowContext->rec;

    fbBasicListClear(&(rec->pop3msg));

}

void ypFreeTFTPRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfTFTPFlow_t *rec = (yfTFTPFlow_t *)flowContext->rec;
    (void) rec;
}

void ypFreeFTPRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfFTPFlow_t *rec = (yfFTPFlow_t *)flowContext->rec;
    fbBasicList_t *temp = (fbBasicList_t *)rec->ftpBasicListBuf;
    int loop, rc;
    size_t offset;

    fbBasicListClear(&(rec->ftpReturn));
    fbBasicListClear(&(rec->ftpUser));
    fbBasicListClear(&(rec->ftpPass));
    fbBasicListClear(&(rec->ftpType));
    fbBasicListClear(&(rec->ftpRespCode));

    rc = ypAddSpec(NULL, 21, &offset);
    /* Free any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListClear(temp);
        temp++;
    }

}

void ypFreeIMAPRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfIMAPFlow_t *rec = (yfIMAPFlow_t *)flowContext->rec;
    fbBasicList_t *temp = (fbBasicList_t *)rec->imapBasicListBuf;
    int loop, rc;
    size_t offset;


    fbBasicListClear(&(rec->imapCapability));
    fbBasicListClear(&(rec->imapLogin));
    fbBasicListClear(&(rec->imapStartTLS));
    fbBasicListClear(&(rec->imapAuthenticate));
    fbBasicListClear(&(rec->imapCommand));
    fbBasicListClear(&(rec->imapExists));
    fbBasicListClear(&(rec->imapRecent));

    rc = ypAddSpec(NULL, 143, &offset);
    /* Free any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListClear(temp);
        temp++;
    }

}


void ypFreeDNSRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfDNSFlow_t *rec = (yfDNSFlow_t *)flowContext->rec;
    yfDNSQRFlow_t *dns = NULL;

    while ((dns = fbSubTemplateListGetNextPtr(&(rec->dnsQRList), dns))) {
        fbSubTemplateListClear(&(dns->dnsRRList));
    }

    fbSubTemplateListClear(&(rec->dnsQRList));
}

void ypFreeMySQLRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfMySQLFlow_t *rec = (yfMySQLFlow_t *)flowContext->rec;

    fbSubTemplateListClear(&(rec->mysqlList));
}

void ypFreeSSLRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfSSLFlow_t *rec = (yfSSLFlow_t *)flowContext->rec;
    yfSSLCertFlow_t *cert = NULL;

    while ((cert = fbSubTemplateListGetNextPtr(&(rec->sslCertList), cert))) {
        fbSubTemplateListClear(&(cert->issuer));
        fbSubTemplateListClear(&(cert->subject));
        fbSubTemplateListClear(&(cert->extension));
    }

    fbSubTemplateListClear(&(rec->sslCertList));
    fbBasicListClear(&(rec->sslCipherList));
}

void ypFreeRTSPRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfRTSPFlow_t *rec = (yfRTSPFlow_t *)flowContext->rec;
    fbBasicList_t *temp = (fbBasicList_t *)rec->rtspBasicListBuf;
    int loop, rc;
    size_t offset;


    fbBasicListClear(&(rec->rtspURL));
    fbBasicListClear(&(rec->rtspVersion));
    fbBasicListClear(&(rec->rtspReturnCode));
    fbBasicListClear(&(rec->rtspContentLength));
    fbBasicListClear(&(rec->rtspCommand));
    fbBasicListClear(&(rec->rtspContentType));
    fbBasicListClear(&(rec->rtspTransport));
    fbBasicListClear(&(rec->rtspCSeq));
    fbBasicListClear(&(rec->rtspLocation));
    fbBasicListClear(&(rec->rtspPacketsReceived));
    fbBasicListClear(&(rec->rtspUserAgent));
    fbBasicListClear(&(rec->rtspJitter));

    rc = ypAddSpec(NULL, 554, &offset);
    /* Free any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListClear(temp);
        temp++;
    }


}

void ypFreeSIPRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfSIPFlow_t *rec = (yfSIPFlow_t *)flowContext->rec;
    fbBasicList_t *temp = (fbBasicList_t *)rec->sipBasicListBuf;
    int loop, rc;
    size_t offset;

    fbBasicListClear(&(rec->sipInvite));
    fbBasicListClear(&(rec->sipCommand));
    fbBasicListClear(&(rec->sipVia));
    fbBasicListClear(&(rec->sipMaxForwards));
    fbBasicListClear(&(rec->sipAddress));
    fbBasicListClear(&(rec->sipContentLength));
    fbBasicListClear(&(rec->sipUserAgent));

    rc = ypAddSpec(NULL, 5060, &offset);
    /* Free any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListClear(temp);
        temp++;
    }

}

void ypFreeSMTPRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfSMTPFlow_t *rec = (yfSMTPFlow_t *)flowContext->rec;
    fbBasicList_t *temp = (fbBasicList_t *)rec->smtpBasicListBuf;
    int loop, rc;
    size_t offset;

    fbBasicListClear(&(rec->smtpHello));
    fbBasicListClear(&(rec->smtpFrom));
    fbBasicListClear(&(rec->smtpTo));
    fbBasicListClear(&(rec->smtpContentType));
    fbBasicListClear(&(rec->smtpSubject));
    fbBasicListClear(&(rec->smtpFilename));
    fbBasicListClear(&(rec->smtpContentDisposition));
    fbBasicListClear(&(rec->smtpResponse));
    fbBasicListClear(&(rec->smtpEnhanced));
    fbBasicListClear(&(rec->smtpSize));
    fbBasicListClear(&(rec->smtpDate));

    rc = ypAddSpec(NULL, 25, &offset);
    /* Free any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListClear(temp);
        temp++;
    }
}

void ypFreeSSHRec(
    ypDPIFlowCtx_t *flowContext)
{

    yfSSHFlow_t *rec = (yfSSHFlow_t *)flowContext->rec;
    fbBasicList_t *temp = (fbBasicList_t *)rec->sshBasicListBuf;
    int loop, rc;
    size_t offset;

    fbBasicListClear(&(rec->sshVersion));

    rc = ypAddSpec(NULL, 22, &offset);
    /* Free any user-defined elements */
    for (loop = 0; loop < rc; loop++) {
        fbBasicListClear(temp);
        temp++;
    }
}

void ypFreeNNTPRec(
    ypDPIFlowCtx_t *flowContext)
{
    yfNNTPFlow_t *rec = (yfNNTPFlow_t *)flowContext->rec;

    fbBasicListClear(&(rec->nntpResponse));
    fbBasicListClear(&(rec->nntpCommand));
}

/**
 * ypGetDNSQName
 *
 * Does the DNS Name Compression Pointer Follow Game - returns the
 * length of the name
 *
 */
uint8_t ypGetDNSQName(
    uint8_t           *buf,
    uint16_t          bufoffset,
    uint8_t           *payload,
    unsigned int      payloadSize,
    uint16_t          *offset)
{

    uint16_t          nameSize;
    uint16_t          toffset = *(offset);
    gboolean          pointer_flag = FALSE;
    int               pointer_depth = 0;
    uint8_t           temp_buf[DNS_MAX_NAME_LENGTH + 1];
    int               temp_buf_size = 0;

    while ( toffset < payloadSize ) {

        if ( 0 == *(payload + toffset) ) {
            if ( !pointer_flag ) {
                *offset += 1;
            }
            temp_buf[temp_buf_size] = '\0';
            toffset = 0;
            break;
        } else if (DNS_NAME_COMPRESSION ==
            (*(payload + toffset) & DNS_NAME_COMPRESSION))
        {
            if ( (toffset + 1) >= payloadSize ) {
                /*Incomplete Name Pointer */
                return 0;
            }
            toffset = ntohs(*((uint16_t *)(payload + toffset)));
            toffset = DNS_NAME_OFFSET & toffset;
            pointer_depth += 1;

            if ( pointer_depth > DNS_MAX_NAME_LENGTH ) {
                /* Too many pointers in DNS name */
                return 0;
            }

            if ( !pointer_flag ) {
                *offset += sizeof(uint16_t);
                pointer_flag = TRUE;
            }

            continue;

        } else {

            nameSize = *(payload + toffset);
            if ( (nameSize + temp_buf_size + 1) > DNS_MAX_NAME_LENGTH ) {
                /* DNS Name Too Long */
                return 0;
            }
            memcpy(temp_buf + temp_buf_size, (payload + toffset + 1),
                   nameSize);
            temp_buf[temp_buf_size + nameSize] = '.';
            temp_buf_size += nameSize + 1;
            if (!pointer_flag) {
                *offset += *(payload + toffset) + 1;
            }

            toffset += nameSize + 1;
        }
    }

    if (toffset >= payloadSize) {
        /*DNS Name outside payload */
        return 0;
    }

    if (bufoffset + temp_buf_size > dpi_user_total_limit) {
        /* Name too large to export in allowed buffer size*/
        return 0;
    }

    /* skip trailing '.' */
    memcpy(buf + bufoffset, temp_buf, temp_buf_size);
    bufoffset += temp_buf_size;

    return temp_buf_size;
}

void ypDNSParser(
    yfDNSQRFlow_t        **dnsQRecord,
    uint8_t              *payload,
    unsigned int         payloadSize,
    uint8_t              *buf,
    unsigned int         *bufLen,
    uint8_t              recordCount)
{

    ycDnsScanMessageHeader_t header;
    uint16_t                 payloadOffset = sizeof(ycDnsScanMessageHeader_t);
    size_t                   nameLen;
    uint8_t                  nxdomain = 0;
    unsigned int             bufSize = (*bufLen);
    uint16_t                 rrType;
    unsigned int             loop;

    ycDnsScanRebuildHeader(payload, &header);

    if (header.rcode == 3) {
        nxdomain = 1;
    }

#if defined(YAF_ENABLE_DNSAUTH)
    if (header.aa) {
        /* get the query part if authoritative */
        nxdomain = 1;
    }
#endif
    for (loop = 0; loop < header.qdcount; loop++) {
        nameLen = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                &payloadOffset);
        if ((!header.qr || nxdomain)) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
            (*dnsQRecord)->dnsQName.len = nameLen;
            (*dnsQRecord)->dnsQName.buf = buf + bufSize;
            bufSize += (*dnsQRecord)->dnsQName.len;
            (*dnsQRecord)->dnsAuthoritative = header.aa;
            (*dnsQRecord)->dnsNXDomain = header.rcode;
            (*dnsQRecord)->dnsRRSection = 0;
            (*dnsQRecord)->dnsQueryResponse = header.qr;
            (*dnsQRecord)->dnsID = header.id;
            if (payloadOffset < payloadSize) {
                (*dnsQRecord)->dnsQRType = ntohs(*((uint16_t *)(payload +
                                                        payloadOffset)));
            }

            recordCount--;
            if (recordCount)
                (*dnsQRecord)++;
            else {
                *bufLen = bufSize;
                return;
            }
        }

        payloadOffset += (sizeof(uint16_t) * 2);
        /* skip over class */
        if (payloadOffset > payloadSize) {
            goto err;
        }

    }

    for (loop = 0; loop < header.ancount; loop++) {
        (*dnsQRecord)->dnsRRSection = 1;
        (*dnsQRecord)->dnsAuthoritative = header.aa;
        (*dnsQRecord)->dnsNXDomain = header.rcode;
        (*dnsQRecord)->dnsQueryResponse = 1;
        (*dnsQRecord)->dnsID = header.id;
        rrType = ypDnsScanResourceRecord(dnsQRecord, payload, payloadSize,
                                         &payloadOffset, buf, &bufSize);

        if (rrType != 41) {
            recordCount--;
            if (recordCount)
                (*dnsQRecord)++;
            else {
                *bufLen = bufSize;
                return;
            }
        }

        if (payloadOffset > payloadSize) {
            goto err;
        }

        if (bufSize > dpi_user_total_limit) {
            bufSize = dpi_user_total_limit;
            goto err;
        }

    }

    for (loop = 0; loop < header.nscount; loop++) {
        (*dnsQRecord)->dnsRRSection = 2;
        (*dnsQRecord)->dnsAuthoritative = header.aa;
        (*dnsQRecord)->dnsNXDomain = header.rcode;
        (*dnsQRecord)->dnsQueryResponse = 1;
        (*dnsQRecord)->dnsID = header.id;
        rrType = ypDnsScanResourceRecord(dnsQRecord, payload, payloadSize,
                                         &payloadOffset, buf, &bufSize);

        if (rrType != 41) {
            recordCount--;
            if (recordCount)
                (*dnsQRecord)++;
            else {
                *bufLen = bufSize;
                return;
            }
        }

        if (payloadOffset > payloadSize) {
            goto err;
        }

        if (bufSize > dpi_user_total_limit) {
            bufSize = dpi_user_total_limit;
            goto err;
        }
    }

    for (loop = 0; loop < header.arcount; loop++) {
        (*dnsQRecord)->dnsRRSection = 3;
        (*dnsQRecord)->dnsAuthoritative = header.aa;
        (*dnsQRecord)->dnsNXDomain = header.rcode;
        (*dnsQRecord)->dnsQueryResponse = 1;
        (*dnsQRecord)->dnsID = header.id;
        rrType = ypDnsScanResourceRecord(dnsQRecord, payload, payloadSize,
                                         &payloadOffset, buf, &bufSize);

        if (rrType != 41) {
            recordCount--;
            if (recordCount)
                (*dnsQRecord)++;
            else {
                *bufLen = bufSize;
                return;
            }
        }

        if (payloadOffset > payloadSize) {
            goto err;
        }


        if (bufSize > dpi_user_total_limit) {
            bufSize = dpi_user_total_limit;
            goto err;
        }
    }

    *bufLen = bufSize;
    return;

err:
    *bufLen = bufSize;
    /* something went wrong so we need to pad the rest of the STL with NULLs */
    /* Most likely we ran out of space in the DNS Export Buffer */
    while (recordCount) {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,YAF_DNSA_FLOW_TID,
                              dnsATemplate, 0);
        recordCount--;
        if (recordCount) (*dnsQRecord)++;
    }

    return;
}

static
uint16_t ypDnsScanResourceRecord(
    yfDNSQRFlow_t                **dnsQRecord,
    uint8_t                      *payload,
    unsigned int                 payloadSize,
    uint16_t                     *offset,
    uint8_t                      *buf,
    unsigned int                 *bufLen)
{

    uint16_t                    nameLen;
    uint16_t                    rrLen;
    uint16_t                    rrType;
    uint16_t                    temp_offset;
    uint16_t                    bufSize = (*bufLen);

    nameLen = ypGetDNSQName(buf, bufSize, payload, payloadSize, offset);
    (*dnsQRecord)->dnsQName.len = nameLen;
    (*dnsQRecord)->dnsQName.buf = buf + bufSize;
    bufSize += (*dnsQRecord)->dnsQName.len;

    rrType = ntohs(*((uint16_t *)(payload + (*offset))));
    (*dnsQRecord)->dnsQRType = rrType;

    /* skip class */
    *offset += (sizeof(uint16_t) * 2 );

    /* time to live */
    (*dnsQRecord)->dnsTTL = ntohl(*((uint32_t *)(payload + (*offset))));
    *offset += sizeof(uint32_t);

    if (*offset >= payloadSize) {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                              YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        return rrType;
    }

    rrLen = ntohs(*(uint16_t *)(payload + (*offset)));
    /* past length field */
    *offset += sizeof(uint16_t);

    if (*offset >= payloadSize) {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                              YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        return rrType;
    }

    temp_offset = (*offset);

    if (rrType == 1) {
        yfDNSAFlow_t *arecord = (yfDNSAFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSA_FLOW_TID, dnsATemplate, 1);
        arecord->ip = ntohl(*((uint32_t *)(payload + temp_offset)));

    } else if (rrType == 2) {
        yfDNSNSFlow_t *nsrecord = (yfDNSNSFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSNS_FLOW_TID, dnsNSTemplate, 1);
        nsrecord->nsdname.len = ypGetDNSQName(buf, bufSize, payload,
                                              payloadSize, &temp_offset);
        nsrecord->nsdname.buf = buf + bufSize;
        bufSize += nsrecord->nsdname.len;

    } else if (rrType == 5) {
        yfDNSCNameFlow_t *cname = (yfDNSCNameFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSCN_FLOW_TID, dnsCNTemplate, 1);
        cname->cname.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                         &temp_offset);
        cname->cname.buf = buf + bufSize;
        bufSize += cname->cname.len;

    } else if (rrType == 12) {
        yfDNSPTRFlow_t *ptr = (yfDNSPTRFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSPTR_FLOW_TID, dnsPTRTemplate, 1);
        ptr->ptrdname.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                          &temp_offset);
        ptr->ptrdname.buf = buf + bufSize;
        bufSize += ptr->ptrdname.len;

    } else if (rrType == 15) {
        yfDNSMXFlow_t *mx = (yfDNSMXFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSMX_FLOW_TID, dnsMXTemplate, 1);
        mx->preference = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);
        if (temp_offset > payloadSize) {
            mx->exchange.len = 0;
            return rrType;
        }
        mx->exchange.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                         &temp_offset);
        mx->exchange.buf = buf + bufSize;
        bufSize += mx->exchange.len;

    } else if (rrType == 16) {
        yfDNSTXTFlow_t *txt = (yfDNSTXTFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSTXT_FLOW_TID, dnsTXTTemplate, 1);
        txt->txt_data.len = *(payload + temp_offset);
        if (txt->txt_data.len + bufSize > dpi_user_total_limit) {
            temp_offset += txt->txt_data.len + 1;
            txt->txt_data.len = 0;
        } else {
            temp_offset++;
            txt->txt_data.buf = payload + temp_offset;
            bufSize += txt->txt_data.len;
            temp_offset += txt->txt_data.len;
        }

    } else if (rrType == 28) {
        yfDNSAAAAFlow_t *aa = (yfDNSAAAAFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSAAAA_FLOW_TID, dnsAAAATemplate, 1);
        memcpy(aa->ip, (payload + temp_offset), sizeof(aa->ip));

    } else if (rrType == 6) {
        yfDNSSOAFlow_t *soa = (yfDNSSOAFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSSOA_FLOW_TID, dnsSOATemplate, 1);
        soa->mname.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                       &temp_offset);
        soa->mname.buf = buf + bufSize;
        bufSize += soa->mname.len;

        if (temp_offset > payloadSize) {
            soa->rname.len = 0;
            return rrType;
        }
        soa->rname.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                       &temp_offset);
        soa->rname.buf = buf + bufSize;
        bufSize += soa->rname.len;
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        soa->serial = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        soa->refresh = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        soa->retry = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        soa->expire = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        soa->minimum = ntohl(*((uint32_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint32_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }

    } else if (rrType == 33) {
        yfDNSSRVFlow_t *srv = (yfDNSSRVFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSSRV_FLOW_TID, dnsSRVTemplate, 1);
        srv->dnsPriority = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        srv->dnsWeight = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        srv->dnsPort = ntohs(*((uint16_t *)(payload + temp_offset)));
        temp_offset += sizeof(uint16_t);
        if (temp_offset >= payloadSize) {
            return rrType;
        }
        srv->dnsTarget.len = ypGetDNSQName(buf, bufSize, payload, payloadSize,
                                           &temp_offset);
        srv->dnsTarget.buf = buf + bufSize;
        bufSize += srv->dnsTarget.len;
        if (temp_offset >= payloadSize) {
            return rrType;
        }

    } else if (rrType == 43) {
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSDSFlow_t *ds = NULL;
            ds =(yfDNSDSFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSDS_FLOW_TID, dnsDSTemplate, 1);
            ds->dnsKeyTag = ntohs(*((uint16_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint16_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            ds->dnsAlgorithm = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset >= payloadSize) {
                return rrType;
            }
            ds->dnsDigestType = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset >= payloadSize) {
                return rrType;
            }
            /* length of rrdata is rrLen - we know these 3 fields */
            /* should add up to 4 - so rest is digest */
            if ((temp_offset + (rrLen - 4)) >= payloadSize) {
                return rrType;
            }

            ds->dnsDigest.buf = payload + temp_offset;
            ds->dnsDigest.len = rrLen - 4;
        }
    } else if (rrType == 46) {
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSRRSigFlow_t *rrsig = NULL;
            rrsig = (yfDNSRRSigFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSRRSIG_FLOW_TID, dnsRRSigTemplate, 1);

            rrsig->dnsTypeCovered = ntohs(*((uint16_t *)(payload +
                                                         temp_offset)));
            temp_offset += sizeof(uint16_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsAlgorithm = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsLabels = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsTTL = ntohl(*((uint32_t *)(payload + temp_offset)));

            temp_offset += sizeof(uint32_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsSigExp = ntohl(*((uint32_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint32_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsSigInception = ntohl(*((uint32_t *)(payload +
                                                          temp_offset)));
            temp_offset += sizeof(uint32_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsKeyTag = ntohs(*((uint16_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint16_t);
            if (temp_offset >= payloadSize) {
                return rrType;
            }

            rrsig->dnsSigner.len = ypGetDNSQName(buf, bufSize, payload,
                                                 payloadSize, &temp_offset);
            rrsig->dnsSigner.buf = buf + bufSize;
            bufSize += rrsig->dnsSigner.len;

            /* signature is at offset 18 + signer's name len */
            if ((temp_offset + (rrLen - 18 + rrsig->dnsSigner.len)) >=
                payloadSize)
            {
                return rrType;
            }
            rrsig->dnsSignature.buf = payload + temp_offset;
            rrsig->dnsSignature.len = (rrLen - 18 - rrsig->dnsSigner.len);
        }
    } else if (rrType == 47) {
        /* NSEC */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSNSECFlow_t *nsec = NULL;
            nsec = (yfDNSNSECFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSNSEC_FLOW_TID, dnsNSECTemplate, 1);
            nsec->dnsHashData.len = ypGetDNSQName(buf, bufSize, payload,
                                                  payloadSize, &temp_offset);
            nsec->dnsHashData.buf = buf + bufSize;
            bufSize += nsec->dnsHashData.len;
            /* subtract next domain name and add record len. forget bitmaps. */
            temp_offset = temp_offset - nsec->dnsHashData.len + rrLen;
        }
    } else if (rrType == 48) {
        /* DNSKEY RR */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            yfDNSKeyFlow_t *dnskey = NULL;
            dnskey = (yfDNSKeyFlow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSKEY_FLOW_TID, dnsKeyTemplate, 1);
            dnskey->dnsFlags = ntohs(*((uint16_t *)(payload + temp_offset)));
            temp_offset += sizeof(uint16_t);

            if (temp_offset >= payloadSize) {
                return rrType;
            }
            dnskey->protocol = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset >= payloadSize) {
                return rrType;
            }
            dnskey->dnsAlgorithm = *(payload + temp_offset);
            temp_offset++;

            if ((temp_offset - 4 + rrLen) >= payloadSize) {
                return rrType;
            } else {
                dnskey->dnsPublicKey.buf = payload + temp_offset;
                dnskey->dnsPublicKey.len = rrLen - 4;
            }
        }
    } else if (rrType == 50 || rrType == 51) {
        /* NSEC3(PARAM)? */
        if (!dnssec) {
            fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                                  YAF_DNSA_FLOW_TID, dnsATemplate, 0);
        } else {
            uint16_t off_hold = temp_offset;
            yfDNSNSEC3Flow_t *nsec3 = NULL;
            nsec3 = (yfDNSNSEC3Flow_t *)fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0, YAF_DNSNSEC3_FLOW_TID, dnsNSEC3Template, 1);
            nsec3->dnsAlgorithm = *(payload + temp_offset);

            /* skip over flags */
            temp_offset += sizeof(uint16_t);

            if (temp_offset >= payloadSize) {
                return rrType;
            }

            nsec3->iterations = ntohs(*((uint16_t *)(payload + temp_offset)));

            temp_offset += sizeof(uint16_t);

            if (temp_offset >= payloadSize) {
                return rrType;
            }

            nsec3->dnsSalt.len = *(payload + temp_offset);
            temp_offset++;
            if (temp_offset + nsec3->dnsSalt.len >= payloadSize) {
                nsec3->dnsSalt.len = 0;
                return rrType;
            }
            nsec3->dnsSalt.buf = payload + temp_offset;
            temp_offset += nsec3->dnsSalt.len;

            if (rrType == 50) {
                nsec3->dnsNextDomainName.len = *(payload + temp_offset);
                temp_offset++;
                if (temp_offset + nsec3->dnsNextDomainName.len >= payloadSize)
                {
                    nsec3->dnsNextDomainName.len = 0;
                    return rrType;
                }
                nsec3->dnsNextDomainName.buf = payload + temp_offset;
                temp_offset = off_hold + rrLen;
            }
        }
    } else {
        fbSubTemplateListInit(&((*dnsQRecord)->dnsRRList), 0,
                              YAF_DNSA_FLOW_TID, dnsATemplate, 0);
    }

    *offset += rrLen;

    *bufLen = bufSize;
    return rrType;
}


uint16_t ypDecodeLength(
    uint8_t           *payload,
    uint16_t          *offset)
{
    uint16_t          obj_len;

    obj_len = *(payload + *offset);
    if (obj_len == CERT_1BYTE) {
        (*offset)++;
        obj_len = *(payload + *offset);
    } else if (obj_len == CERT_2BYTE) {
        (*offset)++;
        obj_len = ntohs(*(uint16_t *)(payload + *offset));
        (*offset)++;
    }

    return obj_len;
}

uint16_t ypDecodeTLV(
    yf_asn_tlv_t      *tlv,
    uint8_t           *payload,
    uint16_t          *offset)
{
    uint8_t            val = *(payload + *offset);
    uint16_t           len = 0;

    tlv->class = (val & 0xD0) >> 6;
    tlv->p_c = (val & 0x20) >> 5;
    tlv->tag = (val & 0x1F);

    (*offset)++;

    len = ypDecodeLength(payload, offset);
    (*offset)++;

    if (tlv->tag == CERT_NULL) {
        *offset += len;
        return ypDecodeTLV(tlv, payload, offset);
    }

    return len;

}


uint8_t ypGetSequenceCount(
    uint8_t          *payload,
    uint16_t         seq_len)
{
    uint16_t         offsetptr = 0;
    uint16_t         len = 0;
    uint16_t         obj_len;
    uint8_t          count = 0;
    yf_asn_tlv_t     tlv;

    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    while (tlv.tag == CERT_SET && len < seq_len) {
        len += obj_len + 2;
        count++;
        offsetptr += obj_len;
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    }

    return count;
}

uint8_t ypGetExtensionCount(
    uint8_t                *payload,
    uint16_t                ext_len)
{

    uint16_t               offsetptr = 0;
    yf_asn_tlv_t           tlv;
    uint16_t               len = 2;
    uint16_t               obj_len = 0;
    uint16_t               id_ce;
    uint8_t                obj_type = 0;
    uint8_t                count = 0;

    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    while (tlv.tag == CERT_SEQ && len < ext_len) {
        len += obj_len + 2;
        if (*(payload + offsetptr) == CERT_OID) {
            id_ce = ntohs(*(uint16_t *)(payload + offsetptr + 2));
            if (id_ce == CERT_IDCE) {
                obj_type = *(payload + offsetptr + 4);
                switch (obj_type) {
                  case 14:
                    /* subject key identifier */
                  case 15:
                    /* key usage */
                  case 16:
                    /* private key usage period */
                  case 17:
                    /* alternative name */
                  case 18:
                    /* alternative name */
                  case 29:
                    /* authority key identifier */
                  case 31:
                    /* CRL dist points */
                  case 32:
                    /* Cert Policy ID */
                  case 35:
                    /* Authority Key ID */
                  case 37:
                    count++;
                  default:
                    break;
                }
            }
        }
        offsetptr += obj_len;
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    }

    return count;
}




gboolean ypDecodeSSLCertificate(
    yfSSLCertFlow_t         **sslCert,
    uint8_t                 *payload,
    unsigned int            payloadSize,
    yfFlow_t                *flow,
    uint16_t                offsetptr)
{
    uint32_t                sub_cert_len;
    uint8_t                 seq_count;
    uint8_t                 obj_type = 0;
    yf_asn_tlv_t            tlv;
    yfSSLObjValue_t         *sslObject = NULL;
    uint16_t                obj_len;
    uint16_t                set_len;
    uint16_t                off_hold;
    uint16_t                id_ce;


    /* we should start with the length of inner cert */
    if (offsetptr + 5 > payloadSize) {
        return FALSE;
    }

    sub_cert_len = (ntohl(*(uint32_t *)(payload + offsetptr)) & 0xFFFFFF00)>>8;

    /* only continue if we have enough payload for the whole cert */
    if (offsetptr + sub_cert_len > payloadSize) {
        return FALSE;
    }

    offsetptr += 3;

    /* this is a CERT which is a sequence with length > 0x7F [0x30 0x82]*/

    if (ntohs(*(uint16_t *)(payload + offsetptr)) != 0x3082) {
        return FALSE;
    }

    /* 2 bytes for above, 2 for length of CERT */
    /* Next we have a signed CERT so 0x3082 + length */

    offsetptr += 8;

    /* A0 is for explicit tagging of Version Number */
    /* 03 is an Integer - 02 is length, 01 is for tagging */
    if (*(payload + offsetptr) == CERT_EXPLICIT) {
        offsetptr += 4;
        (*sslCert)->version = *(payload + offsetptr);
        offsetptr++;
    } else {
        /* default version is version 1 [0] */
        (*sslCert)->version = 0;
    }

    /* serial number */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len > sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag == CERT_INT) {
        (*sslCert)->serial.buf = payload + offsetptr;
        (*sslCert)->serial.len = obj_len;
    }
    offsetptr += obj_len;

    /* signature */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len > sub_cert_len) {
        return FALSE;
    }

    if (tlv.tag != CERT_SEQ) {
        offsetptr += obj_len;
    } else {
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (tlv.tag == CERT_OID) {
            if (obj_len > sub_cert_len) {
                return FALSE;
            }
            (*sslCert)->sig.buf = payload + offsetptr;
            (*sslCert)->sig.len = obj_len;
        }
        offsetptr += obj_len;
    }

    /* issuer - sequence */

    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len > sub_cert_len) {
        return FALSE;
    }

    if (tlv.tag == CERT_SEQ) {
        seq_count = ypGetSequenceCount((payload + offsetptr), obj_len);
    } else {
        return FALSE;
    }

    sslObject = (yfSSLObjValue_t *)fbSubTemplateListInit(&((*sslCert)->issuer),
                                                         0,
                                                      YAF_SSL_SUBCERT_FLOW_TID,
                                                         sslSubTemplate,
                                                         seq_count);
    while (seq_count && sslObject) {
        set_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (set_len >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SET) {
            break;
        }
        off_hold = offsetptr;
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SEQ) {
            break;
        }
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }

        if (tlv.tag != CERT_OID) {
            break;
        }
        if (obj_len != 3) {
            /* this isn't the usual id-at - so lets ignore it */
            sslObject++;
            seq_count--;
            offsetptr = off_hold + set_len;
            continue;
        }

        offsetptr += 2;
        sslObject->obj_id = *(payload + offsetptr);
        offsetptr += 2;
        sslObject->obj_value.len = ypDecodeLength(payload, &offsetptr);
        if (sslObject->obj_value.len >= sub_cert_len) {
            sslObject->obj_value.len = 0;
            return FALSE;
        }
        offsetptr++;
        /* OBJ VALUE */
        sslObject->obj_value.buf = payload + offsetptr;
        offsetptr += sslObject->obj_value.len;
        seq_count--;
        sslObject++;
    }

    /* VALIDITY is a sequence of times */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_SEQ) {
        return FALSE;
    }

    /* notBefore time */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag != CERT_TIME) {
        return FALSE;
    }
    (*sslCert)->not_before.buf = payload + offsetptr;
    (*sslCert)->not_before.len = obj_len;

    offsetptr += obj_len;

    /* not After time */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }
    if (tlv.tag!= CERT_TIME) {
        return FALSE;
    }
    (*sslCert)->not_after.buf = payload + offsetptr;
    (*sslCert)->not_after.len = obj_len;

    offsetptr += obj_len;

    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }

    /* subject - sequence */
    if (tlv.tag == CERT_SEQ) {
        seq_count = ypGetSequenceCount((payload + offsetptr), obj_len);
    } else {
        return FALSE;
    }

    sslObject = (yfSSLObjValue_t *)fbSubTemplateListInit(&((*sslCert)->subject), 0,
                                                         YAF_SSL_SUBCERT_FLOW_TID,
                                                         sslSubTemplate,
                                                         seq_count);

    while (seq_count && sslObject) {
        set_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (set_len >= sub_cert_len) {
            return FALSE;
        }
        off_hold = offsetptr;
        if (tlv.tag != CERT_SET) {
            break;
        }
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }

        if (tlv.tag != CERT_SEQ) {
            break;
        }
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_OID) {
            break;
        }
        if (obj_len != 3) {
            sslObject++;
            seq_count--;
            offsetptr = off_hold + set_len;
            continue;
        }
        offsetptr += 2;
        sslObject->obj_id = *(payload + offsetptr);
        offsetptr += 2;
        sslObject->obj_value.len = ypDecodeLength(payload, &offsetptr);
        if (sslObject->obj_value.len >= sub_cert_len) {
            sslObject->obj_value.len = 0;
            return FALSE;
        }
        offsetptr++;
        /* OBJ VALUE */
        sslObject->obj_value.buf = payload + offsetptr;
        offsetptr += sslObject->obj_value.len;
        seq_count--;
        sslObject++;
    }

    /* subject public key info */
    /* this is a sequence of a sequence of algorithms and public key */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }
    /* this needs to be a sequence */
    if (tlv.tag != CERT_SEQ) {
        offsetptr += obj_len;
    } else {
        /* this is also a seq */
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }
        if (tlv.tag != CERT_SEQ) {
            offsetptr += obj_len;
        } else {
            obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (obj_len >= sub_cert_len) {
                return FALSE;
            }
            /* this is the algorithm id */
            if (tlv.tag == CERT_OID) {
                (*sslCert)->pkalg.buf = payload + offsetptr;
                (*sslCert)->pkalg.len = obj_len;
            }
            offsetptr += obj_len;
            obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (obj_len >= sub_cert_len) {
                return FALSE;
            }
            /* this is the actual public key */
            if (tlv.tag == CERT_BITSTR) {
                (*sslCert)->pklen = obj_len;
            }
            offsetptr += obj_len;
        }
    }

    /* EXTENSIONS! - ONLY AVAILABLE FOR VERSION 3 */
    /* since it's optional - it has a tag if it's here */
    obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
    if (obj_len >= sub_cert_len) {
        return FALSE;
    }

    if ((tlv.class != 2) || ((*sslCert)->version != 2)) {
        /* no extensions */
        fbSubTemplateListInit(&((*sslCert)->extension), 0,
                              YAF_SSL_SUBCERT_FLOW_TID, sslSubTemplate, 0);
    } else {
        uint16_t ext_len;
        obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
        if (obj_len >= sub_cert_len) {
            return FALSE;
        }

        if (tlv.tag == CERT_SEQ) {
            seq_count = ypGetExtensionCount((payload + offsetptr), obj_len);
        } else {
            return FALSE;
        }
        /* extensions */
        sslObject =
            (yfSSLObjValue_t *)fbSubTemplateListInit(&((*sslCert)->extension),
                                                     0,
                                                     YAF_SSL_SUBCERT_FLOW_TID,
                                                     sslSubTemplate,
                                                     seq_count);
        /* exts is a sequence of a sequence of {id, critical flag, value} */
        while (seq_count && sslObject) {
            ext_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (ext_len >= sub_cert_len) {
                return FALSE;
            }

            if (tlv.tag != CERT_SEQ) {
                return FALSE;
            }

            off_hold = offsetptr;
            obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (obj_len >= ext_len) {
                return FALSE;
            }

            if (tlv.tag != CERT_OID) {
                return FALSE;
            }

            id_ce = ntohs(*(uint16_t *)(payload + offsetptr));
            if (id_ce != CERT_IDCE) {
                /* jump past this */
                offsetptr = off_hold + ext_len;
                continue;
            }
            offsetptr += 2;
            obj_type = *(payload + offsetptr);
            offsetptr++;
            obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
            if (obj_len >= ext_len) {
                return FALSE;
            }
            if (tlv.tag == CERT_BOOL) {
                /* this is optional CRITICAL flag */
                offsetptr += obj_len;
                obj_len = ypDecodeTLV(&tlv, payload, &offsetptr);
                if (obj_len >= ext_len) {
                    return FALSE;
                }
            }
            switch (obj_type) {
              case 14:
                /* subject key identifier */
              case 15:
                /* key usage */
              case 16:
                /* private key usage period */
              case 17:
                /* alternative name */
              case 18:
                /* alternative name */
              case 29:
                /* authority key identifier */
              case 31:
                /* CRL dist points */
              case 32:
                /* Cert Policy ID */
              case 35:
                /* Authority Key ID */
              case 37:
                /* ext. key usage */
                sslObject->obj_id = obj_type;
                sslObject->obj_value.len = obj_len;
                sslObject->obj_value.buf = payload + offsetptr;
                offsetptr += obj_len;
                seq_count--;
                sslObject++;
                break;
              default:
                offsetptr = off_hold + ext_len;
                continue;
            }
        }

    }

    return TRUE;

}

#endif
#endif
