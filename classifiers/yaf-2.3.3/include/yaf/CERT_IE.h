/*
 *
 ** @file CERT_IE.h
 ** Definition of the CERT "standard" information elements extension to
 ** the IETF standard RFC 5102 information elements
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2009-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell, Chris Inacio, Emily Ecoff <ecoff@cert.org>
 ** <netsa-help@cert.org>
 ** ------------------------------------------------------------------------
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
 ** ------------------------------------------------------------------------
 */


#ifndef CERT_IE_H_
#define CERT_IE_H_


/**
 * IPFIX information elements in 6871/CERT_PEN space for YAF
 * these elements are included within the capabilities of YAF
 * primarily, but may be used within other CERT software as
 * well
 */
static fbInfoElement_t yaf_info_elements[] = {
    FB_IE_INIT("initialTCPFlags", CERT_PEN, 14, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("unionTCPFlags", CERT_PEN, 15, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("payload", CERT_PEN, 18, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("reverseFlowDeltaMilliseconds", CERT_PEN, 21, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("silkAppLabel", CERT_PEN, 33, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("payloadEntropy", CERT_PEN, 35, 1, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("osName", CERT_PEN, 36, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("osVersion", CERT_PEN, 37, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("firstPacketBanner", CERT_PEN, 38, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("secondPacketBanner", CERT_PEN, 39, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowAttributes", CERT_PEN, 40, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("osFingerPrint", CERT_PEN, 107, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("expiredFragmentCount", CERT_PEN, 100, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("assembledFragmentCount", CERT_PEN, 101, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("meanFlowRate", CERT_PEN, 102, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("meanPacketRate", CERT_PEN, 103, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("flowTableFlushEventCount", CERT_PEN, 104, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("flowTablePeakCount", CERT_PEN, 105, 4, FB_IE_F_ENDIAN),
    /* flow stats */
    FB_IE_INIT("smallPacketCount", CERT_PEN, 500, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("nonEmptyPacketCount", CERT_PEN, 501, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("dataByteCount", CERT_PEN, 502, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("averageInterarrivalTime", CERT_PEN, 503, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("standardDeviationInterarrivalTime", CERT_PEN, 504, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("firstNonEmptyPacketSize", CERT_PEN, 505, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("maxPacketSize", CERT_PEN, 506, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("firstEightNonEmptyPacketDirections", CERT_PEN, 507, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("standardDeviationPayloadLength", CERT_PEN, 508, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpUrgentCount", CERT_PEN, 509, 4, FB_IE_F_ENDIAN|FB_IE_F_REVERSIBLE),
    FB_IE_INIT("largePacketCount", CERT_PEN, 510, 4, FB_IE_F_ENDIAN|FB_IE_F_REVERSIBLE),
    FB_IE_NULL
};


#if YAF_ENABLE_HOOKS
static fbInfoElement_t yaf_dpi_info_elements[] = {
    FB_IE_INIT("httpServerString", CERT_PEN, 110, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpUserAgent", CERT_PEN, 111, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpGet", CERT_PEN, 112, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpConnection", CERT_PEN, 113, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpVersion", CERT_PEN, 114, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpReferer", CERT_PEN, 115, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpLocation", CERT_PEN, 116, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpHost", CERT_PEN, 117, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpContentLength", CERT_PEN, 118, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpAge", CERT_PEN, 119, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpAccept", CERT_PEN, 120, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpAcceptLanguage", CERT_PEN, 121, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpContentType", CERT_PEN, 122, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpResponse", CERT_PEN, 123, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("pop3TextMessage", CERT_PEN, 124, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("ircTextMessage", CERT_PEN, 125, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("tftpFilename", CERT_PEN, 126, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("tftpMode", CERT_PEN, 127, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("slpVersion", CERT_PEN, 128, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("slpMessageType", CERT_PEN, 129, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("slpString", CERT_PEN, 130, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("ftpReturn", CERT_PEN, 131, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("ftpUser", CERT_PEN, 132, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("ftpPass", CERT_PEN,133, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("ftpType", CERT_PEN,134, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("ftpRespCode", CERT_PEN,135, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("imapCapability", CERT_PEN, 136, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("imapLogin", CERT_PEN, 137, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("imapStartTLS", CERT_PEN, 138, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("imapAuthenticate", CERT_PEN, 139, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("imapCommand", CERT_PEN, 140, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("imapExists", CERT_PEN, 141, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("imapRecent", CERT_PEN, 142, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspURL", CERT_PEN, 143, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspVersion", CERT_PEN, 144, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspReturnCode", CERT_PEN, 145, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspContentLength", CERT_PEN, 146, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspCommand", CERT_PEN, 147, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspContentType", CERT_PEN, 148, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspTransport", CERT_PEN, 149, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspCSeq", CERT_PEN, 150, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspLocation", CERT_PEN, 151, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspPacketsReceived", CERT_PEN, 152, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspUserAgent", CERT_PEN, 153, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtspJitter", CERT_PEN, 154, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sipInvite", CERT_PEN, 155, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sipCommand", CERT_PEN, 156, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sipVia", CERT_PEN, 157, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sipMaxForwards", CERT_PEN, 158, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sipAddress", CERT_PEN, 159, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sipContentLength", CERT_PEN, 160, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sipUserAgent", CERT_PEN, 161, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpHello", CERT_PEN, 162, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpFrom", CERT_PEN, 163, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpTo", CERT_PEN, 164, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpContentType", CERT_PEN, 165, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpSubject", CERT_PEN, 166, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpFilename", CERT_PEN, 167, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpContentDisposition", CERT_PEN, 168, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpResponse", CERT_PEN, 169, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpEnhanced", CERT_PEN, 170, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sshVersion", CERT_PEN, 171, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("nntpResponse", CERT_PEN, 172, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("nntpCommand", CERT_PEN, 173, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsQueryResponse", CERT_PEN, 174, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsQRType", CERT_PEN, 175, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsAuthoritative", CERT_PEN, 176, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsNXDomain", CERT_PEN, 177, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsRRSection", CERT_PEN, 178, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsQName", CERT_PEN, 179, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsCName", CERT_PEN, 180, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsMXPreference", CERT_PEN, 181, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsMXExchange", CERT_PEN, 182, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsNSDName", CERT_PEN, 183, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsPTRDName", CERT_PEN, 184, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslCipher", CERT_PEN, 185, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslClientVersion", CERT_PEN, 186, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslServerCipher", CERT_PEN, 187, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslCompressionMethod", CERT_PEN, 188, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslCertVersion", CERT_PEN, 189, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslCertSignature", CERT_PEN, 190, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslCertSerialNumber", CERT_PEN, 244, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslObjectType", CERT_PEN, 245, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslObjectValue", CERT_PEN, 246, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslCertValidityNotBefore", CERT_PEN, 247, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslCertValidityNotAfter", CERT_PEN, 248, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslPublicKeyAlgorithm", CERT_PEN, 249, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("sslPublicKeyLength", CERT_PEN, 250, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsTTL", CERT_PEN, 199, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsTXTData", CERT_PEN, 208, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOASerial", CERT_PEN, 209, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOARefresh", CERT_PEN, 210, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOARetry", CERT_PEN, 211, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOAExpire", CERT_PEN, 212, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOAMinimum", CERT_PEN, 213, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOAMName", CERT_PEN, 214, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSOARName", CERT_PEN, 215, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSRVPriority", CERT_PEN, 216, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSRVWeight", CERT_PEN, 217, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSRVPort", CERT_PEN, 218, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSRVTarget", CERT_PEN, 219, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpCookie", CERT_PEN, 220, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("httpSetCookie", CERT_PEN, 221, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpSize", CERT_PEN, 222, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("mysqlUsername", CERT_PEN, 223, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("mysqlCommandCode", CERT_PEN, 224, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("mysqlCommandText", CERT_PEN, 225, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsID", CERT_PEN, 226, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsAlgorithm", CERT_PEN, 227, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsKeyTag", CERT_PEN, 228, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSigner", CERT_PEN, 229, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSignature", CERT_PEN, 230, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsDigest", CERT_PEN, 231, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsPublicKey", CERT_PEN, 232, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSalt", CERT_PEN, 233, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsHashData", CERT_PEN, 234, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsIterations", CERT_PEN, 235, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSignatureExpiration", CERT_PEN, 236, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsSignatureInception", CERT_PEN, 237, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsDigestType", CERT_PEN, 238, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsLabels", CERT_PEN, 239, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsTypeCovered", CERT_PEN, 240, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("dnsFlags", CERT_PEN, 241, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("smtpDate", CERT_PEN, 251, FB_IE_VARLEN, FB_IE_F_ENDIAN),
    FB_IE_NULL
};

static fbInfoElement_t yaf_dhcp_info_elements[] = {
    FB_IE_INIT("dhcpFingerPrint", CERT_PEN, 242, FB_IE_VARLEN,
               FB_IE_F_REVERSIBLE),
    FB_IE_INIT("dhcpVendorCode", CERT_PEN, 243, FB_IE_VARLEN,
               FB_IE_F_REVERSIBLE),
    FB_IE_NULL
};


#endif

#endif
