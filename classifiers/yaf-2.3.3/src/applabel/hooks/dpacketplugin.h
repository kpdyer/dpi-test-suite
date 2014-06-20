/**
 * @internal
 *
 * @file dpacketplugin.h
 *
 * header file for dpacketplugin.c
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

#include <yaf/autoinc.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#else
#if   HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if   HAVE_MALLOC_H
#include <malloc.h>
#endif
#endif

#if YAF_ENABLE_HOOKS
#include <ctype.h>

/**glib, we use the hash and the error string stuff */
#include <glib.h>
#include <glib/gstdio.h>

#if YAF_ENABLE_APPLABEL

/** we obviously need some yaf details -- we're a plugin to it afterall! */
#include <yaf/yafcore.h>
#include <yaf/decode.h>
#include <yaf/CERT_IE.h>
#include <yaf/yafhooks.h>
#include "payloadScanner.h"
#include <pcre.h>


/* ASN.1 Tag Numbers (for SSL) */
#define CERT_BOOL               0x01
#define CERT_INT                0x02
#define CERT_BITSTR             0x03
#define CERT_OCTSTR             0x04
#define CERT_NULL               0x05
/* Object Identifer */
#define CERT_OID                0x06
/* Start of Sequence */
#define CERT_SEQ                0x10
/* Start of Set */
#define CERT_SET                0x11
/* Printable String */
#define CERT_PRINT              0x13
/* UTC Time */
#define CERT_TIME               0x17
#define CERT_EXPLICIT           0xa0
/* ASN.1 P/C Bit (primitive, constucted) */
#define CERT_PRIM               0x00
#define CERT_CONST              0x01
/* ASN.1 Length 0x81 is length follows in 1 byte */
#define CERT_1BYTE              0x81
/* ASN.1 Length 0x82 is length follows in 2 bytes */
#define CERT_2BYTE              0x82
#define CERT_IDCE               0x551D
#define CERT_IDAT               0x5504

#define DNS_NAME_COMPRESSION    0xc0
#define DNS_NAME_OFFSET         0x0FFF

/**
 * Protocol Specific Template IDS - for quick lookup
 *
 */

#define YAF_IRC_FLOW_TID     0xC200
#define YAF_POP3_FLOW_TID    0xC300
#define YAF_TFTP_FLOW_TID    0xC400
#define YAF_SLP_FLOW_TID     0xC500
#define YAF_HTTP_FLOW_TID    0xC600
#define YAF_FTP_FLOW_TID     0xC700
#define YAF_IMAP_FLOW_TID    0xC800
#define YAF_RTSP_FLOW_TID    0xC900
#define YAF_SIP_FLOW_TID     0xCA00
#define YAF_SMTP_FLOW_TID    0xCB00
#define YAF_SSH_FLOW_TID     0xCC00
#define YAF_NNTP_FLOW_TID    0xCD00
#define YAF_DNS_FLOW_TID     0xCE00
#define YAF_DNSQR_FLOW_TID   0xCF00
#define YAF_DNSA_FLOW_TID    0xCE01
#define YAF_DNSAAAA_FLOW_TID 0xCE02
#define YAF_DNSCN_FLOW_TID   0xCE03
#define YAF_DNSMX_FLOW_TID   0xCE04
#define YAF_DNSNS_FLOW_TID   0xCE05
#define YAF_DNSPTR_FLOW_TID  0xCE06
#define YAF_DNSTXT_FLOW_TID  0xCE07
#define YAF_DNSSRV_FLOW_TID  0xCE08
#define YAF_DNSSOA_FLOW_TID  0xCE09
#define YAF_SSL_FLOW_TID      0xCA0A
#define YAF_SSL_CERT_FLOW_TID 0xCA0B
#define YAF_MYSQL_FLOW_TID    0xCE0C
#define YAF_MYSQLTXT_FLOW_TID 0xCE0D
#define YAF_DNSDS_FLOW_TID    0xCE0E
#define YAF_DNSRRSIG_FLOW_TID 0xCE0F
#define YAF_DNSNSEC_FLOW_TID  0xCE11
#define YAF_DNSKEY_FLOW_TID   0xCE12
#define YAF_DNSNSEC3_FLOW_TID 0xCE13
#define YAF_SSL_SUBCERT_FLOW_TID 0xCE14

/**
 * A YAF Deep Packet Inspection Structure.  Holds offsets in the payload as to
 * important stuff that we want to capture (see protocol PCRE rule files)
 *
 */

typedef struct yfDPIData_st {
    /* id of the field we found */
    uint16_t dpacketID;
    /* offset in the payload to the good stuff */
    uint16_t dpacketCapt;
    /* length of good stuff */
    uint16_t dpacketCaptLen;
} yfDPIData_t;

typedef struct ypDPIFlowCtx_st {
    yfDPIData_t       *dpi;
    /* keep track of how much we're exporting per flow */
    size_t            dpi_len;
    /* For Bi-Directional - need to know how many in fwd payload */
    uint8_t           captureFwd;
    /* Total Captures Fwd & Rev */
    uint8_t           dpinum;
    /* Primarily for Uniflow - Since we don't know if it's a FWD or REV flow
       this is set to know where to start in the dpi array */
    uint8_t           startOffset;
    /* For Lists - we need to keep a ptr around so we can free it after
       fBufAppend */
    void              *rec;
    /* extra buffer mainly for DNS stuff for now */
    uint8_t           *exbuf;
} ypDPIFlowCtx_t;


typedef struct ypBLValue_st {
    size_t                BLoffset;
    const fbInfoElement_t *infoElement;
} ypBLValue_t;

typedef struct ypBLKey_st {
    uint16_t              appLabel;
    uint16_t              id;
} ypBLKey_t;


/**
 * DPI Templates and related data structures.
 *
 */

static fbInfoElementSpec_t yaf_singleBL_spec[] = {
    {"basicList",       0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfSSHFlow_st {
    fbBasicList_t sshVersion;
    uint8_t       sshBasicListBuf[0];
} yfSSHFlow_t;

typedef struct yfIRCFlow_st {
    fbBasicList_t ircMsg;
} yfIRCFlow_t;

typedef struct yfPOP3Flow_st {
    fbBasicList_t pop3msg;
} yfPOP3Flow_t;


static fbInfoElementSpec_t yaf_tftp_spec[] = {
    {"tftpFilename",          0, 0 },
    {"tftpMode",              0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfTFTPFlow_st {
    fbVarfield_t tftpFilename;
    fbVarfield_t tftpMode;
} yfTFTPFlow_t;

static fbInfoElementSpec_t yaf_slp_spec[] = {
    {"basicList",             0, 0 },
    {"slpVersion",            0, 0 },
    {"slpMessageType",        0, 0 },
    {"paddingOctets",         6, 1 },
    FB_IESPEC_NULL
};

typedef struct yfSLPFlow_st {
    fbBasicList_t slpString;
    uint8_t     slpVersion;
    uint8_t     slpMessageType;
    uint8_t     padding[6];
} yfSLPFlow_t;

static fbInfoElementSpec_t yaf_http_spec[] = {
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfHTTPFlow_st {
    fbBasicList_t server;
    fbBasicList_t userAgent;
    fbBasicList_t get;
    fbBasicList_t connection;
    fbBasicList_t referer;
    fbBasicList_t location;
    fbBasicList_t host;
    fbBasicList_t contentLength;
    fbBasicList_t age;
    fbBasicList_t response;
    fbBasicList_t acceptLang;
    fbBasicList_t accept;
    fbBasicList_t contentType;
    fbBasicList_t httpVersion;
    fbBasicList_t httpCookie;
    fbBasicList_t httpSetCookie;
    uint8_t       httpBasicListBuf[0];
} yfHTTPFlow_t;


static fbInfoElementSpec_t yaf_ftp_spec[] = {
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfFTPFlow_st {
    fbBasicList_t ftpReturn;
    fbBasicList_t ftpUser;
    fbBasicList_t ftpPass;
    fbBasicList_t ftpType;
    fbBasicList_t ftpRespCode;
    uint8_t       ftpBasicListBuf[0];
} yfFTPFlow_t;

static fbInfoElementSpec_t yaf_imap_spec[] = {
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    {"basicList",        0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfIMAPFlow_st {
    fbBasicList_t imapCapability;
    fbBasicList_t imapLogin;
    fbBasicList_t imapStartTLS;
    fbBasicList_t imapAuthenticate;
    fbBasicList_t imapCommand;
    fbBasicList_t imapExists;
    fbBasicList_t imapRecent;
    uint8_t       imapBasicListBuf[0];
} yfIMAPFlow_t;


static fbInfoElementSpec_t yaf_rtsp_spec[] = {
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfRTSPFlow_st {
    fbBasicList_t rtspURL;
    fbBasicList_t rtspVersion;
    fbBasicList_t rtspReturnCode;
    fbBasicList_t rtspContentLength;
    fbBasicList_t rtspCommand;
    fbBasicList_t rtspContentType;
    fbBasicList_t rtspTransport;
    fbBasicList_t rtspCSeq;
    fbBasicList_t rtspLocation;
    fbBasicList_t rtspPacketsReceived;
    fbBasicList_t rtspUserAgent;
    fbBasicList_t rtspJitter;
    uint8_t       rtspBasicListBuf[0];
} yfRTSPFlow_t;


static fbInfoElementSpec_t yaf_sip_spec[] = {
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfSIPFlow_st {
    fbBasicList_t sipInvite;
    fbBasicList_t sipCommand;
    fbBasicList_t sipVia;
    fbBasicList_t sipMaxForwards;
    fbBasicList_t sipAddress;
    fbBasicList_t sipContentLength;
    fbBasicList_t sipUserAgent;
    uint8_t       sipBasicListBuf[0];
} yfSIPFlow_t;



static fbInfoElementSpec_t yaf_smtp_spec[] = {
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    {"basicList",         0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfSMTPFlow_st {
    fbBasicList_t smtpHello;
    fbBasicList_t smtpFrom;
    fbBasicList_t smtpTo;
    fbBasicList_t smtpContentType;
    fbBasicList_t smtpSubject;
    fbBasicList_t smtpFilename;
    fbBasicList_t smtpContentDisposition;
    fbBasicList_t smtpResponse;
    fbBasicList_t smtpEnhanced;
    fbBasicList_t smtpSize;
    fbBasicList_t smtpDate;
    uint8_t       smtpBasicListBuf[0];
} yfSMTPFlow_t;

static fbInfoElementSpec_t yaf_nntp_spec[] = {
    {"basicList",       0, 0 },
    {"basicList",       0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfNNTPFlow_st {
    fbBasicList_t nntpResponse;
    fbBasicList_t nntpCommand;
} yfNNTPFlow_t;


/**
 * DNS!!!
 *
 */

static fbInfoElementSpec_t yaf_dns_spec[] = {
    {"subTemplateList",    0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSFlow_st {
    fbSubTemplateList_t   dnsQRList;
} yfDNSFlow_t;


static fbInfoElementSpec_t yaf_dnsQR_spec[] = {
    {"subTemplateList",     0, 0 }, /*based on type of RR */
    {"dnsQName",            0, 0 },
    {"dnsTTL",              0, 0 },
    {"dnsQRType",           0, 0 },
    {"dnsQueryResponse",    0, 0 },  /*Q(0) or R(1) - uint8*/
    {"dnsAuthoritative",    0, 0 }, /* authoritative response (1)*/
    {"dnsNXDomain",         0, 0 }, /* nxdomain (1) */
    {"dnsRRSection",        0, 0 }, /*0, 1, 2, 3 (q, ans, auth, add'l) */
    {"dnsID",               0, 0 },
    {"paddingOctets",       4, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSQRFlow_st {
    fbSubTemplateList_t dnsRRList;
    fbVarfield_t        dnsQName;
    uint32_t            dnsTTL;
    uint16_t            dnsQRType;
    uint8_t             dnsQueryResponse;
    uint8_t             dnsAuthoritative;
    uint8_t             dnsNXDomain;
    uint8_t             dnsRRSection;
    uint16_t            dnsID;
    uint8_t             padding[4];
} yfDNSQRFlow_t;


static fbInfoElementSpec_t yaf_dnsA_spec[] = {
    {"sourceIPv4Address",         0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSAFlow_st {
    uint32_t            ip;
} yfDNSAFlow_t;

static fbInfoElementSpec_t yaf_dnsAAAA_spec[] = {
    {"sourceIPv6Address",         0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSAAAAFlow_st {
    uint8_t             ip[16];
} yfDNSAAAAFlow_t;

static fbInfoElementSpec_t yaf_dnsCNAME_spec[] = {
    {"dnsCName",                  0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSCNameFlow_st {
    fbVarfield_t        cname;
} yfDNSCNameFlow_t;

static fbInfoElementSpec_t yaf_dnsMX_spec[] = {
    {"dnsMXExchange",             0, 0 },
    {"dnsMXPreference",           0, 0 },
    {"paddingOctets",             6, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSMXFlow_st {
    fbVarfield_t exchange;
    uint16_t     preference;
    uint8_t      padding[6];
} yfDNSMXFlow_t;

static fbInfoElementSpec_t yaf_dnsNS_spec[] = {
    {"dnsNSDName",                0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSNSFlow_st {
    fbVarfield_t nsdname;
} yfDNSNSFlow_t;

static fbInfoElementSpec_t yaf_dnsPTR_spec[] = {
    {"dnsPTRDName",               0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSPTRFlow_st {
    fbVarfield_t ptrdname;
} yfDNSPTRFlow_t;

static fbInfoElementSpec_t yaf_dnsTXT_spec[] = {
    {"dnsTXTData",                0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSTXTFlow_st {
    fbVarfield_t txt_data;
} yfDNSTXTFlow_t;

static fbInfoElementSpec_t yaf_dnsSOA_spec[] = {
    {"dnsSOAMName",               0, 0 },
    {"dnsSOARName",               0, 0 },
    {"dnsSOASerial",              0, 0 },
    {"dnsSOARefresh",             0, 0 },
    {"dnsSOARetry",               0, 0 },
    {"dnsSOAExpire",              0, 0 },
    {"dnsSOAMinimum",             0, 0 },
    {"paddingOctets",             4, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSSOAFlow_st {
    fbVarfield_t mname;
    fbVarfield_t rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
    uint8_t padding[4];
} yfDNSSOAFlow_t;

static fbInfoElementSpec_t yaf_dnsSRV_spec[] = {
    {"dnsSRVTarget",              0, 0 },
    {"dnsSRVPriority",            0, 0 },
    {"dnsSRVWeight",              0, 0 },
    {"dnsSRVPort",                0, 0 },
    {"paddingOctets",             2, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSSRVFlow_st {
    fbVarfield_t  dnsTarget;
    uint16_t      dnsPriority;
    uint16_t      dnsWeight;
    uint16_t      dnsPort;
    uint8_t       padding[2];
} yfDNSSRVFlow_t;


static fbInfoElementSpec_t yaf_dnsDS_spec[] = {
    {"dnsDigest",                 0, 0 },
    {"dnsKeyTag",                 0, 0 },
    {"dnsAlgorithm",              0, 0 },
    {"dnsDigestType",             0, 0 },
    {"paddingOctets",             4, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSDSFlow_st {
    fbVarfield_t dnsDigest;
    uint16_t     dnsKeyTag;
    uint8_t      dnsAlgorithm;
    uint8_t      dnsDigestType;
    uint8_t      padding[4];
} yfDNSDSFlow_t;


static fbInfoElementSpec_t yaf_dnsSig_spec[] = {
    {"dnsSigner",                 0, 0 },
    {"dnsSignature",              0, 0 },
    {"dnsSignatureInception",     0, 0 },
    {"dnsSignatureExpiration",    0, 0 },
    {"dnsTTL",                    0, 0 },
    {"dnsKeyTag",                 0, 0 },
    {"dnsTypeCovered",            0, 0 },
    {"dnsAlgorithm",              0, 0 },
    {"dnsLabels",                 0, 0 },
    {"paddingOctets",             6, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSRRSigFlow_st {
    fbVarfield_t dnsSigner;
    fbVarfield_t dnsSignature;
    uint32_t     dnsSigInception;
    uint32_t     dnsSigExp;
    uint32_t     dnsTTL;
    uint16_t     dnsTypeCovered;
    uint16_t     dnsKeyTag;
    uint8_t      dnsAlgorithm;
    uint8_t      dnsLabels;
    uint8_t      padding[6];
} yfDNSRRSigFlow_t;

static fbInfoElementSpec_t yaf_dnsNSEC_spec[] = {
    {"dnsHashData",               0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfDNSNSECFlow_st {
    fbVarfield_t dnsHashData;
} yfDNSNSECFlow_t;

static fbInfoElementSpec_t yaf_dnsKey_spec[] = {
    {"dnsPublicKey",              0, 0 },
    {"dnsFlags",                  0, 0 },
    {"protocolIdentifier",        0, 0 },
    {"dnsAlgorithm",              0, 0 },
    {"paddingOctets",             4, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSKeyFlow_st {
    fbVarfield_t dnsPublicKey;
    uint16_t     dnsFlags;
    uint8_t      protocol;
    uint8_t      dnsAlgorithm;
    uint8_t      padding[4];
} yfDNSKeyFlow_t;

static fbInfoElementSpec_t yaf_dnsNSEC3_spec[] = {
    {"dnsSalt",                   0, 0 },
    {"dnsHashData",               0, 0 },
    {"dnsIterations",             0, 0 },
    {"dnsAlgorithm",              0, 0 },
    {"paddingOctets",             5, 1 },
    FB_IESPEC_NULL
};

typedef struct yfDNSNSEC3Flow_st {
    fbVarfield_t dnsSalt;
    fbVarfield_t dnsNextDomainName;
    uint16_t     iterations;
    uint8_t      dnsAlgorithm;
    uint8_t      padding[5];
} yfDNSNSEC3Flow_t;

/**
 * SSL DPI
 *
 */

typedef struct yf_asn_tlv_st {
    uint8_t        class:2;
    uint8_t        p_c:1;
    uint8_t        tag:5;
} yf_asn_tlv_t;

static fbInfoElementSpec_t yaf_ssl_spec[] = {
    {"basicList",                 0, 0 }, /*list of ciphers 32bit */
    {"sslServerCipher",           0, 0 }, /*cipher suite in server hello */
    {"sslClientVersion",          0, 0 },
    {"sslCompressionMethod",      0, 0 }, /*compression method in serv hello*/
    {"paddingOctets",             2, 1 },
    {"subTemplateList",           0, 0 }, /* list of certs */
    FB_IESPEC_NULL
};

typedef struct yfSSLFlow_st {
    fbBasicList_t        sslCipherList;
    uint32_t             sslServerCipher;
    uint8_t              sslClientVersion;
    uint8_t              sslCompressionMethod;
    uint8_t              padding[2];
    fbSubTemplateList_t  sslCertList;
} yfSSLFlow_t;


static fbInfoElementSpec_t yaf_cert_spec[] = {
    {"subTemplateList",             0, 0 },
    {"subTemplateList",             0, 0 },
    {"subTemplateList",             0, 0 },
    {"sslCertSignature",            0, 0 },
    {"sslCertSerialNumber",         0, 0 },
    {"sslCertValidityNotBefore",    0, 0 },
    {"sslCertValidityNotAfter",     0, 0 },
    {"sslPublicKeyAlgorithm",       0, 0 },
    {"sslPublicKeyLength",          0, 0 },
    {"sslCertVersion",              0, 0 },
    {"paddingOctets",               5, 1 },
    FB_IESPEC_NULL
};

typedef struct yfSSLCertFlow_st {
    fbSubTemplateList_t     issuer;
    fbSubTemplateList_t     subject;
    fbSubTemplateList_t     extension;
    fbVarfield_t            sig;
    fbVarfield_t            serial;
    fbVarfield_t            not_before;
    fbVarfield_t            not_after;
    fbVarfield_t            pkalg;
    uint16_t                pklen;
    uint8_t                 version;
    uint8_t                 padding[5];
} yfSSLCertFlow_t;

static fbInfoElementSpec_t yaf_subssl_spec[] = {
    {"sslObjectValue",              0, 0 },
    {"sslObjectType",               0, 0 },
    {"paddingOctets",               7, 1 },
    FB_IESPEC_NULL
};

typedef struct yfSSLObjValue_st {
    fbVarfield_t            obj_value;
    uint8_t                 obj_id;
    uint8_t                 padding[7];
} yfSSLObjValue_t;


/**
 * MySQL
 *
 */

static fbInfoElementSpec_t yaf_mysql_spec[] = {
    {"subTemplateList",            0, 0 },
    {"mysqlUsername",              0, 0 },
    FB_IESPEC_NULL
};

typedef struct yfMySQLFlow_st {
    fbSubTemplateList_t  mysqlList;
    fbVarfield_t         mysqlUsername;
} yfMySQLFlow_t;

static fbInfoElementSpec_t yaf_mysql_txt_spec[] = {
    {"mysqlCommandText",           0, 0 },
    {"mysqlCommandCode",           0, 0 },
    {"paddingOctets",              7, 1 },
    FB_IESPEC_NULL
};

typedef struct yfMySQLTxtFlow_st {
    fbVarfield_t  mysqlCommandText;
    uint8_t       mysqlCommandCode;
    uint8_t       padding[7];
} yfMySQLTxtFlow_t;


/**
 * Initialization functions
 *
 */

void ypParsePluginOpt(
    const char             *option);

gboolean ypInitializeProtocolRules(
    FILE                   *dpiRuleFile,
    GError                 **err);

fbTemplate_t * ypInitTemplate(
    fbSession_t            *session,
    fbInfoElementSpec_t    *spec,
    uint16_t               tid,
    uint32_t               flags,
    GError                 **err);

uint16_t ypProtocolHashSearch(
    uint16_t               portNum,
    uint16_t               insert);

gboolean ypProtocolHashActivate(
    uint16_t               portNum,
    uint16_t               index);

void ypProtocolHashInitialize(void);


/**
 * DPI Essential FUNCTIONS
 *
 */

void ypFillBasicList(
    yfFlow_t         *flow,
    yfDPIData_t      *dpi,
    uint8_t          totalCaptures,
    uint8_t          forwardCaptures,
    fbVarfield_t     **varField,
    uint8_t          *indexArray);

uint8_t ypDPIScanner(
    ypDPIFlowCtx_t   *flowContext,
    const uint8_t    *payloadData,
    unsigned int     payloadSize,
    yfFlow_t         *flow,
    yfFlowVal_t      *val);


/**
 * DPI FREE FUNCTIONS
 *
 */

void ypFreeHTTPRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeSLPRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeSSLRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeIRCRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreePOP3Rec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeTFTPRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeFTPRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeIMAPRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeRTSPRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeSIPRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeSMTPRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeSSHRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeNNTPRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeDNSRec(
    ypDPIFlowCtx_t *flowContext);

void ypFreeMySQLRec(
    ypDPIFlowCtx_t *flowContext);

/**
 * DPI PROCESS FUNCTIONS
 *
 */

void *ypProcessHTTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessSLP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessIRC(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessSSL(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiList_t      *mainRec,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessPOP3(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessTFTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessFTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessIMAP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessRTSP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessSIP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessSMTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessSSH(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessNNTP(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessDNS(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

void *ypProcessMySQL(
    ypDPIFlowCtx_t                *flowContext,
    fbSubTemplateMultiListEntry_t *stml,
    yfFlow_t                      *flow,
    uint8_t                       fwdcap,
    uint8_t                       totalcap,
    uint16_t                      rulePos);

/**
 * DNS PARSING
 *
 */

void ypDNSParser(
    yfDNSQRFlow_t **dnsQRecord,
    uint8_t *payload,
    unsigned int payloadSize,
    uint8_t *buf,
    unsigned int *bufLen,
    uint8_t recordCount);

static
uint16_t ypDnsScanResourceRecord(
    yfDNSQRFlow_t **dnsQRecord,
    uint8_t *payload,
    unsigned int payloadSize,
    uint16_t *offset,
    uint8_t *buf,
    unsigned int *bufLen);

uint8_t ypGetDNSQName(
    uint8_t *buf,
    uint16_t bufoffset,
    uint8_t *payload,
    unsigned int payloadSize,
    uint16_t *offset);


/**
 * SSL CERT Parsing
 *
 */

gboolean ypDecodeSSLCertificate(
    yfSSLCertFlow_t **sslCert,
    uint8_t *payload,
    unsigned int payloadSize,
    yfFlow_t *flow,
    uint16_t offsetptr);
#endif
#endif
