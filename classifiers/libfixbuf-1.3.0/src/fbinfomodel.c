/*
 ** fbinfomodel.c
 ** IPFIX Information Model and IE storage management
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell
 ** ------------------------------------------------------------------------
 ** @OPENSOURCE_HEADER_START@
 ** Use of the libfixbuf system and related source code is subject to the terms
 ** of the following licenses:
 **
 ** GNU Lesser GPL (LGPL) Rights pursuant to Version 2.1, February 1999
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

#define _FIXBUF_SOURCE_
#include <fixbuf/private.h>

#ident "$Id: fbinfomodel.c 18713 2013-02-21 15:34:28Z ecoff_svn $"

struct fbInfoModel_st {
    GHashTable          *ie_table;
    GHashTable          *ie_byname;
    GStringChunk        *ie_names;
};

static fbInfoElement_t defaults[] = {
    FB_IE_INIT("octetDeltaCount", 0, 1, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("packetDeltaCount", 0, 2, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("deltaFlowCount", 0, 3, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("protocolIdentifier", 0, 4, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipClassOfService", 0, 5, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpControlBits", 0, 6, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("sourceTransportPort", 0, 7, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("sourceIPv4Address", 0, 8, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("sourceIPv4PrefixLength", 0, 9, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ingressInterface", 0, 10, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("destinationTransportPort", 0, 11, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("destinationIPv4Address", 0, 12, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("destinationIPv4PrefixLength", 0, 13, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("egressInterface", 0, 14, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipNextHopIPv4Address", 0, 15, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("bgpSourceAsNumber", 0, 16, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("bgpDestinationAsNumber", 0, 17, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("bgpNextHopIPv4Address", 0, 18, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postMCastPacketDeltaCount", 0, 19, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postMCastOctetDeltaCount", 0, 20, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowEndSysUpTime", 0, 21, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowStartSysUpTime", 0, 22, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postOctetDeltaCount", 0, 23, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postPacketDeltaCount", 0, 24, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("minimumIpTotalLength", 0, 25, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("maximumIpTotalLength", 0, 26, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("sourceIPv6Address", 0, 27, 16, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("destinationIPv6Address", 0, 28, 16, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("sourceIPv6PrefixLength", 0, 29, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("destinationIPv6PrefixLength", 0, 30, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowLabelIPv6", 0, 31, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("icmpTypeCodeIPv4", 0, 32, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("igmpType", 0, 33, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowActiveTimeout", 0, 36, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowIdleTimeout", 0, 37, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("exportedOctetTotalCount", 0, 40, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("exportedMessageTotalCount", 0, 41, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("exportedFlowRecordTotalCount", 0, 42, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("sourceIPv4Prefix", 0, 44, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("destinationIPv4Prefix", 0, 45, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsTopLabelType", 0, 46, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsTopLabelIPv4Address", 0, 47, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("minimumTTL", 0, 52, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("maximumTTL", 0, 53, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("fragmentIdentification", 0, 54, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postIpClassOfService", 0, 55, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("sourceMacAddress", 0, 56, 6, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postDestinationMacAddress", 0, 57, 6, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("vlanId", 0, 58, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postVlanId", 0, 59, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipVersion", 0, 60, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowDirection", 0, 61, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipNextHopIPv6Address", 0, 62, 16, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("bgpNextHopIPv6Address", 0, 63, 16, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipv6ExtensionHeaders", 0, 64, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsTopLabelStackSection", 0, 70, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackSection2", 0, 71, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackSection3", 0, 72, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackSection4", 0, 73, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackSection5", 0, 74, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackSection6", 0, 75, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackSection7", 0, 76, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackSection8", 0, 77, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackSection9", 0, 78, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackSection10", 0, 79, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("destinationMacAddress", 0, 80, 6, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postSourceMacAddress", 0, 81, 6, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("interfaceName", 0, 82, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("interfaceDescription", 0, 83, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("octetTotalCount", 0, 85, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("packetTotalCount", 0, 86, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("fragmentOffset", 0, 88, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsVpnRouteDistinguisher", 0, 90, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsTopLabelPrefixLength", 0, 91, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("applicationDescription", 0, 94, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("applicationId", 0, 95, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("applicationName", 0, 96, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("postIpDiffServCodePoint", 0, 98, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("multicastReplicationFactor", 0, 99, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("classificationEngineId", 0, 101, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("bgpNextAdjacentAsNumber", 0, 128, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("bgpPrevAdjacentAsNumber", 0, 129, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("exporterIPv4Address", 0, 130, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("exporterIPv6Address", 0, 131, 16, FB_IE_F_NONE),
    FB_IE_INIT("droppedOctetDeltaCount", 0, 132, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("droppedPacketDeltaCount", 0, 133, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("droppedOctetTotalCount", 0, 134, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("droppedPacketTotalCount", 0, 135, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowEndReason", 0, 136, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("commonPropertiesId", 0, 137, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("observationPointId", 0, 138, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("icmpTypeCodeIPv6", 0, 139, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsTopLabelIPv6Address", 0, 140, 16, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("lineCardId", 0, 141, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("portId", 0, 142, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("meteringProcessId", 0, 143, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("exportingProcessId", 0, 144, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("templateId", 0, 145, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("wlanChannelId", 0, 146, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("wlanSSID", 0, 147, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowId", 0, 148, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("observationDomainId", 0, 149, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("flowStartSeconds", 0, 150, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowEndSeconds", 0, 151, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowStartMilliseconds", 0, 152, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowEndMilliseconds", 0, 153, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowStartMicroseconds", 0, 154, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowEndMicroseconds", 0, 155, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowStartNanoseconds", 0, 156, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowEndNanoseconds", 0, 157, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowStartDeltaMicroseconds", 0, 158, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowEndDeltaMicroseconds", 0, 159, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("systemInitTimeMilliseconds", 0, 160, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowDurationMilliseconds", 0, 161, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowDurationMicroseconds", 0, 162, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("observedFlowTotalCount", 0, 163, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("ignoredPacketTotalCount", 0, 164, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("ignoredOctetTotalCount", 0, 165, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("notSentFlowTotalCount", 0, 166, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("notSentPacketTotalCount", 0, 167, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("notSentOctetTotalCount", 0, 168, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("destinationIPv6Prefix", 0, 169, 16, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("sourceIPv6Prefix", 0, 170, 16, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postOctetTotalCount", 0, 171, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postPacketTotalCount", 0, 172, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("flowKeyIndicator", 0, 173, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("postMCastPacketTotalCount", 0, 174, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postMCastOctetTotalCount", 0, 175, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("icmpTypeIPv4", 0, 176, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("icmpCodeIPv4", 0, 177, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("icmpTypeIPv6", 0, 178, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("icmpCodeIPv6", 0, 179, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("udpSourcePort", 0, 180, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("udpDestinationPort", 0, 181, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpSourcePort", 0, 182, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpDestinationPort", 0, 183, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpSequenceNumber", 0, 184, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpAcknowledgementNumber", 0, 185, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpWindowSize", 0, 186, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpUrgentPointer", 0, 187, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpHeaderLength", 0, 188, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipHeaderLength", 0, 189, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("totalLengthIPv4", 0, 190, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("payloadLengthIPv6", 0, 191, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipTTL", 0, 192, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("nextHeaderIPv6", 0, 193, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsPayloadLength", 0, 194, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipDiffServCodePoint", 0, 195, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipPrecedence", 0, 196, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("fragmentFlags", 0, 197, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("octetDeltaSumOfSquares", 0, 198, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("octetTotalSumOfSquares", 0, 199, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsTopLabelTTL", 0, 200, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackLength", 0, 201, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackDepth", 0, 202, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsTopLabelExp", 0, 203, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipPayloadLength", 0, 204, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("udpMessageLength", 0, 205, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("isMulticast", 0, 206, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipv4IHL", 0, 207, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipv4Options", 0, 208, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpOptions", 0, 209, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("paddingOctets", 0, 210, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("collectorIPv4Address", 0, 211, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("collectorIPv6Address", 0, 212, 16, FB_IE_F_NONE),
    FB_IE_INIT("exportInterface", 0, 213, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("exportProtocolVersion", 0, 214, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("exportTransportProtocol", 0, 215, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("collectorTransportPort", 0, 216, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("exporterTransportPort", 0, 217, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("tcpSynTotalCount", 0, 218, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpFinTotalCount", 0, 219, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpRstTotalCount", 0, 220, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpPshTotalCount", 0, 221, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpAckTotalCount", 0, 222, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpUrgTotalCount", 0, 223, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipTotalLength", 0, 224, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postNATSourceIPv4Address", 0, 225, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("postNATDestinationIPv4Address", 0, 226, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("postNAPTSourceTransportPort", 0, 227, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("postNAPTDestinationTransportPort", 0, 228, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("natOriginatingAddressRealm", 0, 229, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("natEvent", 0, 230, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("initiatorOctets", 0, 231, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("responderOctets", 0, 232, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("firewallEvent", 0, 233, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("ingressVRFID", 0, 234, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("egressVRFID", 0, 235, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("VRFname", 0, 236, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postMplsTopLabelExp", 0, 237, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tcpWindowScale", 0, 238, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("biflowDirection", 0, 239, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("ethernetHeaderLength", 0, 240, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ethernetPayloadLength", 0, 241, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ethernetTotalLength", 0, 242, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("dot1qVlanId", 0, 243, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("dot1qPriority", 0, 244, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("dot1qCustomerVlanId", 0, 245, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("dot1qCustomerPriority", 0, 246, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("metroEvcId", 0, 247, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("metroEvcType", 0, 248, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("pseudoWireId", 0, 249, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("psuedoWireType", 0, 250, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("pseudoWireControlWord", 0, 251, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ingressPhysicalInterface", 0, 252, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("egressPhysicalInterface", 0, 253, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("postDot1qVlanId", 0, 254, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postDot1qCustomerVlanId", 0, 255, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ethernetType", 0, 256, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postIpPrecedence", 0, 257, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("collectionTimeMilliseconds", 0, 258, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("exportSctpStreamId", 0, 259, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("maxExportSeconds", 0, 260, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("maxFlowEndSeconds", 0, 261, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("messageMD5Checksum", 0, 262, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("messageScope", 0, 263, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("minExportSeconds", 0, 264, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("minFlowStartSeconds", 0, 265, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("opaqueOctets", 0, 266, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("sessionScope", 0, 267, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("maxFlowEndMicroseconds", 0, 268, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("maxFlowEndMilliseconds", 0, 269, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("maxFlowEndNanoseconds", 0, 270, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("minFlowStartMicroseconds", 0, 271, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("minFlowStartMilliseconds", 0, 272, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("minFlowStartNanoseconds", 0, 273, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("collectorCertificate", 0, 274, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("exporterCertificate", 0, 275, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("dataRecordsReliability", 0, 276, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("observationPointType", 0, 277, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("connectionCountNew", 0, 278, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("connectionSumDuration", 0, 279, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("connectionTransactionId", 0, 280, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("postNATSourceIPv6Address", 0, 281, 16, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("postNATDestinationIPv6Address", 0, 282, 16, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("natPoolID", 0, 283, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("natPoolName", 0, 284, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("anonymizationFlags", 0, 285, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("anonymizationTechnique", 0, 286, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("informationElementIndex", 0, 287, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("p2pTechnology", 0, 288, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("tunnelTechnology", 0, 289, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("encryptedTechnology", 0, 290, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("basicList", 0, FB_IE_BASIC_LIST, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("subTemplateList", 0, FB_IE_SUBTEMPLATE_LIST, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("subTemplateMultiList", 0, FB_IE_SUBTEMPLATE_MULTILIST, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("bgpValidityState", 0, 294, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("IPSecSPI", 0, 295, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("greKey", 0, 296, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("natType", 0, 297, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("initiatorPackets", 0, 298, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("responderPackets", 0, 299, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("observationDomainName", 0, 300, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("selectionSequenceId", 0, 301, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("selectorId", 0, 302, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("informationElementId", 0, 303, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("selectorAlgorithm", 0, 304, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("samplingPacketInterval", 0, 305, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("samplingPacketSpace", 0, 306, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("samplingTimeInterval", 0, 307, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("samplingTimeSpace", 0, 308, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("samplingSize", 0, 309, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("samplingPopulation", 0, 310, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("samplingProbability", 0, 311, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipHeaderPacketSection", 0, 313, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ipPayloadPacketSection", 0, 314, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("dataLinkFrameSection", 0, 315, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsLabelStackSection", 0, 316, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("mplsPayloadPacketSection", 0, 317, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("selectorIdTotalPktsObserved", 0, 318, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("selectorIdTotalPktsSelected", 0, 319, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("absoluteError", 0, 320, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("relativeError", 0, 321, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("observationTimeSeconds", 0, 322, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("observationTimeMilliseconds", 0, 323, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("observationTimeMicroseconds", 0, 324, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("observationTimeNanoseconds", 0, 325, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("digestHashValue", 0, 326, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("hashIPPayloadOffset", 0, 327, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("hashIPPayloadSize", 0, 328, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("hashOutputRangeMin", 0, 329, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("hashOutputRangeMax", 0, 330, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("hashSelectedRangeMin", 0, 331, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("hashSelectedRangeMax", 0, 332, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("hashDigestOutput", 0, 333, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("hashInitialiserValue", 0, 334, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("selectorName", 0, 335, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("upperCILimit", 0, 336, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("lowerCILimit", 0, 337, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("confidenceLevel", 0, 338, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("informationElementDataType", 0, 339, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("informationElementDescription", 0, 340, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("informationElementName", 0, 341, FB_IE_VARLEN, FB_IE_F_REVERSIBLE),
    FB_IE_INIT("informationElementRangeBegin", 0, 342, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("informationElementRangeEnd", 0, 343, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("informationElementSemantics", 0, 344, 1, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("informationElementUnits", 0, 345, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("privateEnterpriseNumber", 0, 346, 4, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("virtualStationInterfaceId", 0, 347, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("virtualStationInterfaceName", 0, 348, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("virtualStationUUID", 0, 349, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("virtualStationName", 0, 350, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("layer2SegmentId", 0, 351, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("layer2OctetDeltaCount", 0, 352, 8, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("layer2octetTotalCount", 0, 353, 8, FB_IE_F_ENDIAN|FB_IE_F_REVERSIBLE),
    FB_IE_INIT("ingressUnicastPacketTotalCount", 0, 354, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("ingressMulticastPacketTotalCount", 0, 355, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("ingressBroadcastPacketTotalCount", 0, 356, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("egressUnicastPacketTotalCount", 0, 357, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("egressBroadcastPacketTotalCount", 0, 358, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("monitoringIntervalStartMilliSeconds", 0, 359, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("monitoringIntervalEndMilliSeconds", 0, 360, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("portRangeStart", 0, 361, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("portRangeEnd", 0, 362, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("portRangeStepSize", 0, 363, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("portRangeNumPorts", 0, 364, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("staMacAddress", 0, 365, 6, FB_IE_F_ENDIAN),
    FB_IE_INIT("staIPv4Address", 0, 366, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("wtpMacAddress", 0, 367, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("ingressInterfaceType", 0, 368, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("egressInterfaceType", 0, 369, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("rtpSequenceNumber", 0, 370, 2, FB_IE_F_ENDIAN | FB_IE_F_REVERSIBLE),
    FB_IE_INIT("userName", 0, 371, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("applicationCategoryName", 0, 372, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("applicationSubCategoryName", 0, 373, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("applicationGroupName", 0, 374, FB_IE_VARLEN, FB_IE_F_NONE),
    FB_IE_INIT("originalFLowsPresent", 0, 375, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("originalFLowsInitiated", 0, 376, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("originalFLowsCompleted", 0, 377, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("distinctCountOfSourceIPAddress", 0, 378, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("distinctCountOfDestinationIPAddress", 0, 379, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("distinctCountOfSourceIPv4Address", 0, 380, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("distinctCountOfDestinationIPv4Address", 0, 381, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("distinctCountOfSourceIPv6Address", 0, 382, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("distinctCountOfDestinationIPv6Address", 0, 383, 8, FB_IE_F_ENDIAN),
    FB_IE_INIT("valueDistributionMethod", 0, 384, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("rfc3550JitterMilliseconds", 0, 385, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("rfc3550JitterMicroseconds", 0, 386, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("rfc3550JitterNanoseconds", 0, 387, 4, FB_IE_F_ENDIAN),
    FB_IE_INIT("NF_F_FW_EXT_EVENT", 0, FB_CISCO_ASA_EVENT_XTRA, 2, FB_IE_F_ENDIAN),
    FB_IE_INIT("NF_F_FW_EVENT", 0, FB_CISCO_ASA_EVENT_ID, 1, FB_IE_F_ENDIAN),
    FB_IE_INIT("ciscoNetflowGeneric", 0, FB_CISCO_GENERIC, 8, FB_IE_F_ENDIAN),
    FB_IE_NULL
};

uint32_t            fbInfoElementHash(
    fbInfoElement_t     *ie)
{
    return ((ie->ent & 0x0000ffff) << 16) | (ie->num << 2) | (ie->midx << 4);
}

gboolean            fbInfoElementEqual(
    const fbInfoElement_t   *a,
    const fbInfoElement_t   *b)
{
    return ((a->ent == b->ent) && (a->num == b->num) && (a->midx == b->midx));
}

void                fbInfoElementDebug(
    gboolean            tmpl,
    fbInfoElement_t     *ie)
{
    if (ie->len == FB_IE_VARLEN) {
        fprintf(stderr, "VL %02x %08x:%04x %2u (%s)\n",
                    ie->flags, ie->ent, ie->num, ie->midx,
                    tmpl ? ie->ref.canon->ref.name : ie->ref.name);
    } else {
        fprintf(stderr, "%2u %02x %08x:%04x %2u (%s)\n",
                    ie->len, ie->flags, ie->ent, ie->num, ie->midx,
                    tmpl ? ie->ref.canon->ref.name : ie->ref.name);
    }
}

static void         fbInfoElementFree(
    fbInfoElement_t     *ie)
{
    g_slice_free(fbInfoElement_t, ie);
}

fbInfoModel_t       *fbInfoModelAlloc()
{
    fbInfoModel_t       *model = NULL;

    /* Create an information model */
    model = g_slice_new0(fbInfoModel_t);

    /* Allocate information element tables */
    model->ie_table = g_hash_table_new_full(
            (GHashFunc)fbInfoElementHash, (GEqualFunc)fbInfoElementEqual,
            NULL, (GDestroyNotify)fbInfoElementFree);

    model->ie_byname = g_hash_table_new(g_str_hash, g_str_equal);

    /* Allocate information element name chunk */
    model->ie_names = g_string_chunk_new(64);

    /* Add IETF information elements to the information model */
    fbInfoModelAddElementArray(model, defaults);

    /* Return the new information model */
    return model;
}

void                fbInfoModelFree(
    fbInfoModel_t       *model)
{
    g_hash_table_destroy(model->ie_byname);
    g_string_chunk_free(model->ie_names);
    g_hash_table_destroy(model->ie_table);
    g_slice_free(fbInfoModel_t, model);
}

static void         fbInfoModelReversifyName(
    const char          *fwdname,
    char                *revname,
    size_t              revname_sz)
 {
    /* paranoid string copy */
    strncpy(revname + FB_IE_REVERSE_STRLEN, fwdname, revname_sz - FB_IE_REVERSE_STRLEN - 1);
    revname[revname_sz - 1] = (char)0;

    /* uppercase first char */
    revname[FB_IE_REVERSE_STRLEN] = toupper(revname[FB_IE_REVERSE_STRLEN]);

    /* prepend reverse */
    memcpy(revname, FB_IE_REVERSE_STR, FB_IE_REVERSE_STRLEN);
}

#define FB_IE_REVERSE_BUFSZ 256

void                fbInfoModelAddElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ie)
{
    fbInfoElement_t     *model_ie = NULL;
    char                revname[FB_IE_REVERSE_BUFSZ];

    /* Allocate a new information element */
    model_ie = g_slice_new0(fbInfoElement_t);

    /* Copy external IE to model IE */
    model_ie->ref.name = g_string_chunk_insert(model->ie_names, ie->ref.name);
    model_ie->midx = 0;
    model_ie->ent = ie->ent;
    model_ie->num = ie->num;
    model_ie->len = ie->len;
    model_ie->flags = ie->flags;

    /* Insert model IE into tables */
    g_hash_table_insert(model->ie_table, model_ie, model_ie);
    g_hash_table_insert(model->ie_byname, (char *)model_ie->ref.name, model_ie);

    /* Short circuit if not reversible or not IANA-managed */
    if (!(ie->flags & FB_IE_F_REVERSIBLE)) {
        return;
    }

    /* Allocate a new reverse information element */
    model_ie = g_slice_new0(fbInfoElement_t);

    /* Generate reverse name */
    fbInfoModelReversifyName(ie->ref.name, revname, sizeof(revname));

    /* Copy external IE to reverse model IE */
    model_ie->ref.name = g_string_chunk_insert(model->ie_names, revname);
    model_ie->midx = 0;
    model_ie->ent = ie->ent ? ie->ent : FB_IE_PEN_REVERSE;
    model_ie->num = ie->ent ? ie->num | FB_IE_VENDOR_BIT_REVERSE : ie->num;
    model_ie->len = ie->len;
    model_ie->flags = ie->flags;

    /* Insert model IE into tables */
    g_hash_table_insert(model->ie_table, model_ie, model_ie);
    g_hash_table_insert(model->ie_byname, (char *)model_ie->ref.name, model_ie);
}

void                fbInfoModelAddElementArray(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ie)
{
    for (; ie->ref.name; ie++) fbInfoModelAddElement(model, ie);
}

const fbInfoElement_t     *fbInfoModelGetElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ex_ie)
{
    return g_hash_table_lookup(model->ie_table, ex_ie);
}

gboolean            fbInfoElementCopyToTemplate(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ex_ie,
    fbInfoElement_t     *tmpl_ie)
{
    const fbInfoElement_t     *model_ie = NULL;

    /* Look up information element in the model */
    model_ie = fbInfoModelGetElement(model, ex_ie);
    if (!model_ie) {
        /* Information element not in model. Note it's alien and add it. */
        ex_ie->ref.name = g_string_chunk_insert(model->ie_names,
                                                "_alienInformationElement");
        ex_ie->flags |= FB_IE_F_ALIEN;
        fbInfoModelAddElement(model, ex_ie);
        model_ie = fbInfoModelGetElement(model, ex_ie);
        g_assert(model_ie);
    }

    /* Refer to canonical IE in the model */
    tmpl_ie->ref.canon = model_ie;

    /* Copy model IE to template IE */
    tmpl_ie->midx = 0;
    tmpl_ie->ent = model_ie->ent;
    tmpl_ie->num = model_ie->num;
    tmpl_ie->len = ex_ie->len;
    tmpl_ie->flags = model_ie->flags;

    /* All done */
    return TRUE;
}

const fbInfoElement_t     *fbInfoModelGetElementByName(
    fbInfoModel_t       *model,
    const char          *name)
{
    return g_hash_table_lookup(model->ie_byname, name);
}

const fbInfoElement_t    *fbInfoModelGetElementByID(
    fbInfoModel_t      *model,
    uint16_t           id,
    uint32_t           ent)
{

    fbInfoElement_t tempElement;

    tempElement.midx = 0;
    tempElement.ent = ent;
    tempElement.num = id;

    return fbInfoModelGetElement(model, &tempElement);
}

gboolean            fbInfoElementCopyToTemplateByName(
    fbInfoModel_t       *model,
    const char          *name,
    uint16_t            len_override,
    fbInfoElement_t     *tmpl_ie)
{
    const fbInfoElement_t     *model_ie = NULL;

    /* Look up information element in the model */
    model_ie = fbInfoModelGetElementByName(model, name);
    if (!model_ie) return FALSE;

    /* Refer to canonical IE in the model */
    tmpl_ie->ref.canon = model_ie;

    /* Copy model IE to template IE */
    tmpl_ie->midx = 0;
    tmpl_ie->ent = model_ie->ent;
    tmpl_ie->num = model_ie->num;
    tmpl_ie->len = len_override ? len_override : model_ie->len;
    tmpl_ie->flags = model_ie->flags;

    /* All done */
    return TRUE;
}
