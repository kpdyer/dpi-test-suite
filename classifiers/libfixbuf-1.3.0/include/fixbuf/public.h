/*
 ** public.h
 ** fixbuf IPFIX Implementation Public Interface
 **
 ** ------------------------------------------------------------------------
 ** Copyright (C) 2006-2013 Carnegie Mellon University. All Rights Reserved.
 ** ------------------------------------------------------------------------
 ** Authors: Brian Trammell, Dan Ruef
 ** ------------------------------------------------------------------------
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
 ** ------------------------------------------------------------------------
 */

/**
 * @mainpage libfixbuf - IPFIX Protocol Library
 *
 * @section Introduction
 *
 * libfixbuf is a compliant implementation of the IPFIX Protocol,
 * as defined in the "Specification of the IPFIX Protocol for the Export of IP
 * Flow Information" (RFC 5101). It supports the information model
 * defined in "Information Model for IP Flow Information Export"
 * (RFC 5102), extended as proposed by "Bidirectional Flow Export using
 * IPFIX" (RFC 5103) to support information elements for representing biflows.
 *
 * libfixbuf supports UDP, TCP, SCTP, TLS over TCP, and Spread as transport
 * protocols. Support for DTLS over UDP and DTLS over SCTP is forthcoming.
 * It also supports operation as an IPFIX File Writer or IPFIX File Reader as
 * defined in "An IPFIX-Based File Format" (draft-trammell-ipfix-file, current
 * revision -05).
 *
 * As of version 1.0, libfixbuf supports structured data elements as described
 * in "Export of Structured Data in IPFIX" (RFC 6313).  This adds the ability
 * to export basicLists, subTemplateLists, and subTemplateMultiLists.

 * libfixbuf's public API is defined in public.h; see the documentation of
 * that file for general documentation on getting started with libfixbuf, as
 * well as detailed documentation on the public API calls and data types.
 *
 * @section Downloading
 *
 * libfixbuf is distributed from http://tools.netsa.cert.org/fixbuf
 *
 * @section Building
 *
 * libfixbuf uses a reasonably standard autotools-based build system.
 * The customary build procedure (<tt>./configure && make
 * && make install</tt>) should work in most environments.
 *
 * libfixbuf requires glib-2.0 version 2.6.4 or later. If built against
 * version 2.10 or later, it will automatically use the glib slab allocator
 * for increased memory allocation performance. glib is available on most
 * modern Linux distributions and BSD ports collections, or in source form from
 * <a href="http://www.gtk.org">http://www.gtk.org</a>.
 *
 * libfixbuf automatically uses the getaddrinfo(3) facility and the
 * accompanying dual IPv4/IPv6 stack support if present. getaddrinfo(3)
 * must be present to export or collect flows over IPv6.
 *
 * libfixbuf does not build with SCTP support by default. The --with-sctp
 * option must be given to the libfixbuf ./configure script to include SCTP
 * support. Also note that SCTP requires kernel support, and applications
 * built against libfixbuf with libsctp may fail at runtime if that kernel
 * support is not present.
 *
 * libfixbuf does not build with TLS support by default. The --with-openssl
 * option must be given to the libfixbuf ./configure script to include TLS
 * support.
 *
 * Spread support requires <a href="http://www.spread.org">Spread</a> 4.1 or
 * later. libfixbuf does not build with Spread support by default.
 * The --with-spread option must be given to libfixbuf ./configure script to
 * include Spread support.
 *
 * @section Known Issues
 *
 * The following are known issues with libfixbuf as of version 1.0.0:
 *
 * <ul>
 * <li>There is no support for DTLS over UDP or DTLS over SCTP transport.</li>
 * <li>There is no support for application-selectable SCTP stream assignment
 *     or SCTP partial reliability. Templates are sent reliably on stream 0,
 *     and data sets are sent reliably on stream 1.
 * </li>
 * <li>There is no automatic support for periodic template retransmission
 *     or periodic template expiration as required when transporting IPFIX
 *     over UDP. Applications using libfixbuf to transport IPFIX messages
 *     over UDP must maintain these timeouts and manually manage the session.
 *     However, inactive UDP collector sessions are timed out after 30 minutes,
 *     at which time the session is freed and all templates associated with the
 *     session are removed.
 * </li>
 * </ul>
 *
 * @section Copyright
 *
 * libfixbuf is copyright 2005-2013 Carnegie Mellon University, and is released
 * under the GNU Lesser General Public License (LGPL). See the COPYING file in
 * the distribution for details.
 *
 * libfixbuf was developed at the CERT Network Situational Awareness Group
 * by Brian Trammell and the CERT Network Situational Awareness Group
 * Engineering Team for use in the NAF and YAF tools.
 */

/**
 * @file
 *
 * fixbuf IPFIX protocol library public interface. Include fixbuf/public.h
 * in order to use the public fixbuf API. Calls defined in this header file
 * will not change from version to version after fixbuf 1.0.0.
 *
 * This documentation uses IPFIX terminology as defined in RFC 5101,
 * "Specification of the IPFIX Protocol for the Exchange of IP Traffic Flow
 * Information"
 *
 * @section types Data Types
 *
 * This file defines the data types and routines required to support IPFIX
 * Exporting Process and IPFIX Collecting Process creation. Each data type is
 * manipulated primarily by routines named "fb" followed by the type name
 * (e.g., "Session", "Collector") followed by a description of the routine's
 * action. The routines operating on the fBuf_t IPFIX Mesaage buffer type are
 * named beginning with "fBuf".
 *
 * The fBuf_t opaque type implements a transcoding IPFIX Message buffer for
 * both export and collection, and is the "core" interface to the fixbuf
 * library.
 *
 * The fbInfoModel_t opaque type implements an IPFIX Information Model,
 * including both IANA managed Information Elements and vendor-specific
 * Information Elements. The fbTemplate_t opaque type implements an IPFIX
 * Template or an IPFIX Options Template. Both are defined in terms of
 * Information Elements, represented by the fbInfoElement_t public type.
 * An fBuf_t message buffer maintains internal Templates, which represent
 * records within the fixbuf application client, and external Templates,
 * which represent records as they appear on the wire, for use during
 * transcoding. For a Spread Exporter, Templates are managed per group.  For
 * a Spread Collector, Templates are managed per Session.
 *
 * The state of an IPFIX Transport Session, including IPFIX Message Sequence
 * Number tracking and the internal and external Templates in use within the
 * Session, are maintained by the fbSession_t opaque type.
 *
 * An Exporting Process' connection to its corresponding Collecting Process
 * is encapsulated by the fbExporter_t opaque type. Exporters may be created
 * to connect via the network using one of the supported IPFIX transport
 * protocols, or to write to IPFIX Files specified by name or by open ANSI C
 * file pointer.
 *
 * A Collecting Process' connection to a corresponding Exporting Process is
 * encapsulated by the fbCollector_t opaque type. The passive connection used
 * to listen for connections from Exporting Processes is managed by the
 * fbListener_t opaque type; Collectors can be made to read from IPFIX Files
 * specified directly by name or by open ANSI C file pointer, as well.
 *
 * Network addresses are specified for Exporters, Collectors, and Listeners
 * using the fbConnSpec_t and fbTransport_t public types.
 *
 * This file also defines the GError error codes used by all the fixbuf types
 * and routines within the FB_ERROR_DOMAIN domain.
 *
 * @section export Exporter Usage
 *
 * Each fixbuf application must have a single fbInfoModel_t instance that
 * represents the Information Elements that the application understands.
 * The fbInfoModelAlloc() call allocates a new Information Model with the
 * IANA-managed information elements (current as of the fixbuf release date)
 * preloaded. Additional vendor-specific information elements may be added
 * with fbInfoModelAddElement() and fbInfoModelAddElementArray().
 *
 * To create an Exporter, first create an fbSession_t attached to the
 * application's fbInfoModel_t to hold the Exporter's Transport Session
 * state using fbSessionAlloc(). If exporting via the Spread protocol, create
 * an fbSpreadParams_t and set its session to your newly defined session,
 * group names (a null terminated array), and Spread daemon name.
 *
 * Then create an fbExporter_t to encapsulate the connection to the
 * Collecting Process or the file on disk, using the fbExporterAllocFP(),
 * fbExporterAllocFile(), fbExporterAllocNet(), or fbExporterAllocSpread()
 * calls.
 *
 * With an fbSession_t and an fbExporter_t available, create a buffer for
 * writing via fBufAllocForExport(). Set the internal and external template
 * IDs with fBufSetInternalTemplate() and fBufSetExportTemplate(), and use
 * fBufAppend() to write records into IPFIX Messages and Messages to the
 * output stream.
 *
 * Create and populate templates for addition to this session using the
 * fbTemplate calls, then add them to the session via fbSessionAddTemplate().
 * If exporting via Spread, before calling fbSessionAddTemplate(), set the
 * group that should receive this template with the fBufSetSpreadExportGroup()
 * call.  If more than 1 group should receive the template, use the
 * fbSessionAddTemplatesMulticast() which will call fBufSetSpreadExportGroup()
 * on the given group(s) multicast the template to the given group(s).
 * For Spread, do not use fbSessionAddTemplate() to send to multiple groups.
 *
 * Note that Templates use internal reference counting, so they may be added
 * to multiple sessions, or to the same session using multiple template IDs or
 * multiple domains, or as both an internal and an external template on the
 * same session.
 *
 * By default, fBufAppend() will emit an IPFIX Message to the output stream
 * when the end of the message buffer is reached on write. The
 * fBufSetAutomaticMode() call can be used to modify this behavior,
 * causing fBufAppend() to return FB_ERROR_EOM when at end of message. Use
 * this if your application requires manual control of message export. In this
 * case, fBufEmit() will emit a Message to the output stream.  If using Spread,
 * call fBufSetSpreadExportGroup() to set the groups to export to on the
 * buffer before calling fBufAppend().
 *
 * @section read Collector Usage - Reading from IPFIX Files
 *
 * Using fixbuf to read from IPFIX Files as a Collecting Process is very
 * much like the Export case. Create an fbInfoModel_t and an fbSession_t as
 * above, though you should not define external templates in the new session
 * for collection (instead requiring them to be loaded from templates in the
 * file).
 *
 * Then create an fbCollector_t to encapsulate the file, using the
 * fbCollectorAllocFP() or fbCollectorAllocFile() calls.
 *
 * With an fbSession_t and an fbCollector_t available, create a buffer for
 * writing via fBufAllocForCollection(). Set the internal template
 * ID with fBufSetInternalTemplate(), and use
 * fBufNext() to read records from IPFIX Messages and Messages from the
 * input stream.
 *
 * By default, fBufNext() will consume an IPFIX Message from the input stream
 * when the end of the message buffer is reached on read. The
 * fBufSetAutomaticMode() call can be used to modify this behavior,
 * causing fBufNext() to return FB_ERROR_EOM when at end of message. Use
 * this if your application requires manual control of message collection.
 * In this case, fBufNextMessage() will consume a Message from the input
 * stream.
 *
 * @section collect Collector Usage - Listening to the Network
 *
 * An additional type, fbListener_t, is used to build Collecting Processes
 * to listen for connections from IPFIX Exporting Processes via the network.
 * To use a listener, first create an fbInfoModel_t and an fbSession_t as
 * above, without defining any external templates. Instead of maintaining
 * state for a particular Transport Session, this fbSession_t instance will
 * be used as a template for each Transport Session created by the listener.
 *
 * Then create an fbListener_t to encapsulate a passive socket on the network
 * to wait for connections from Exporting Processes using the
 * fbListenerAlloc() call.
 *
 * To wait for a connection from an Exporting Process, call fbListenerWait(),
 * which handles the cloning of the fbSession_t, the creation of the
 * fbCollector_t, and the creation of the buffer for reading from that
 * collector, and returns the newly created fBuf_t instance.
 *
 * Each listener tracks every active collector/buffer (i.e., each active
 * Session) it created; the fbListenerWait() call will return an fBuf_t from
 * which another IPFIX Message may be read if no new connections are available.
 * The preferred parameter may be used to request an fBuf_t to try first, to
 * minimize switching among available Sessions. See the documentation for
 * fbListenerWait() for more details.
 *
 * @section udp - IPFIX over UDP
 *
 * It is not recommended to use UDP for IPFIX transport, since
 * UDP is not a reliable transport protocol, and therefore cannot guarantee
 * the delivery ofmessages.  libfixbuf stores sequence numbers and reports
 * protential loss of messages.  Templates over UDP must be re-sent at regular
 * intervals.  Fixbuf does not automatically retransmit messages at regular
 * intervals, it is left to the application author to call
 * fbSessionExportTemplates().  In accordance with RFC 5101, the templates
 * should be resent at least three times in the Template refresh timeout
 * period.  Make sure the record size does not exceed the path MTU.
 * libfixbuf will return an error if the message exceeds the path MTU.
 *
 * A UDP collector session is associated with a unique IP, observation domain
 * pair.  UDP sessions timeout after 30 minutes of inactivity.  When a session
 * times out, all templates and state are discarded, this includes any related
 * NetFlow v9 templates and/or state.  libfixbuf will discard
 * any data records for which it does not contain a template for. Template IDs
 * are unique per UDP session (IP and Observation Domain.) Once
 * templates are refreshed, old templates may not be used or referenced by
 * the collecting session.  A UDP collector manages multiple sessions on
 * one collector and fbuf.  If the application is using the fbListenerAppInit
 * and fbListenerAppFree functions to maintain context per session, it is
 * necessary to call fbCollectorGetContext() after each call to fBufNext() to
 * receive the correct ctx pointer (as opposed to calling it after
 * fbListenerWait() returns in the TCP case).  If the application needs to
 * manage context PER SESSION, the application must turn on multi-session mode
 * w/ fbCollectorSetUDPMultiSession() (this allows for backwards compatibility
 * with old applications.)  Previously, the appinit() function was called
 * only from fbListenerAlloc() for UDP connections, which did not allow the
 * application the peer information.  The appinit() function is now called
 * during fbListenerAlloc() (with a NULL peer address) and also when
 * a new UDP connection is made to the collector, giving the application
 * veto power over session creation.  If the application does not call
 * fbCollectorSetUDPMultiSession(), the application will not receive the
 * callback to it's appinit() function, which only allows the application
 * to set one ctx pointer on all sessions.  Likewise, appfree() is only
 * called once, when the collector is freed, if not in multi-session mode.
 * If the application is in multi-session mode, appfree() will be called
 * once for each session when the collector is freed AND anytime a session
 * is timed out.

 * Note: If the appinit() function returns FALSE, libfixbuf will
 * reject any subsequent messages from the
 * peer address, observation domain until the timeout period has expired.
 *
 * To only accept IPFIX from one host without using the appinit() and
 * appfree() functions, it is encouraged to
 * use fbCollectorSetAcceptOnly().  UDP messages received from other hosts
 * will return FB_ERROR_NLREAD.  The application should ignore errors with
 * this error code by clearing the error and calling fBufNext().
 *
 * To manage netflow v9 and UDP sessions by port as well as IP and
 * observation domain, use fbCollectorManageUDPStreamByPort().  Some
 * netflow v9 devices send two separate streams from different ports to
 * the same sensor.  Unless the observation domain is different on each
 * of the streams, use fbCollectorManageUDPStreamByPort() to prevent
 * template confusion between streams.
 *
 *
 * @section NetFlow v9 Collector Usage
 *
 * libfixbuf can be used as a NetFlow v9 collector and convert NetFlow to
 * IPFIX.  Follow the steps above to create an fbListener.  After creating
 * the listener, retrieve the collector by calling fbListenerGetCollector()
 * before calling fbCollectorSetNetflowV9Translator().  Fixbuf can decode all
 * NetFlow v9 information elements up to 346.  Since fixbuf removes the
 * SysUpTime from the NetFlow v9 Header, when fixbuf encounters elements 21
 * and 22 (which rely on the SysUpTime to determine flow start and end times)
 * it will add IPFIX Element 160 (systemInitTimeMilliseconds) to the template
 * and corresponding flow record. systemInitTimeMilliseconds is the Packet
 * Export Time (found in the NetFlow v9 Header) converted to milliseconds
 * minus the SysUpTime. Also, for arbitrary Cisco Elements (ID > 346), fixbuf
 * will convert the element ID to 9999 in order to decode the element properly.
 * The exceptions are elements 33002 (NF_F_FW_EXT_EVENT) and 40005
 * (NF_F_FW_EVENT) which are often exported from Cisco's ASA device. These
 * elements will be converted to their corresponding element id's in
 * libfixbuf's default Information Model, 9997 and 9998 respectively.
 * Similarly, the Cisco ASA will also export elements 40001, 40002, 40003, and
 * 40004.  These elements are substituted with the IPFIX elements 225, 226,
 * 227, and 228 respectively.
 *
 * libfixbuf differentiates Netflow v9 streams by IP and observation domain.
 * If no activity is seen from a NetFlow v9 exporter within 30 minutes, the
 * session and all the templates associated with it will be freed. It is best
 * to set the template timeout period on the device to under 30 minutes.
 *
 * fbCollectorGetNetflowMissed() can be used to retrieve the number of
 * potential missed export packets.  This is not the number of FLOW records
 * that the collector has missed.  NetFlow v9 increases sequence numbers
 * by the number of export packets it has sent, NOT the number of flow
 * records.  An export packet may not contain any flow records.  Fixbuf
 * tries to account for any reboot of the device and not count large
 * sequence number discrepancies in it's missed count.
 *
 * @section Spread Collector Usage - Using the Spread Protocol
 *
 * Similar to reading from IPFIX Files, Create an fbInfoModel_t and an
 * fbSession_t as above, though you should not define external templates
 * in the new session for collection (instead requiring them to be sent
 * from the group that you are subscribing to).  Define an fbSpreadParams_t
 * and set the session, groups to subscribe to, and Spread Daemon name.
 *
 * Then create an fbCollector_t to connect and listen to the Spread Daemon
 * using fbCollectorAllocSpread().
 *
 * With an fbSession_t and fbcollector_t available, create a buffer for
 * writing via fBufAllocForCollection().  Set the internal template ID with
 * fBufSetInternalTemplate(), and use fBufNext() to read records from IPFIX
 * Messages published to the group your collector is subscribing to.
 *
 * To view all the Spread Groups that were sent the incoming record, call
 * fbCollectorGetSpreadReturnGroups() on the collector.
 *
 * @section lists Lists in IPFIX
 *
 * @subsection general General Information
 * Each of the list structures uses a nested list of data.
 * The basic list nests a single information element, while the others use a
 * nested template.  The template used for nesting is part of the listed
 * templates sent to the collector when the connection is made, or when the
 * data transfer begins.  There is no way to mark a template from this list as
 * one that will be nested, or one that will be used as the highest level
 * template.  Each of the templates in the list are treated as equals.
 *
 * The collector does not learn which template or information element is nested
 * until the data arrives.  This requires flexbility in the collectors to
 * handle each of the possible results.
 *
 * @subsubsection internalTemplates Internal Templates for Sub Templates
 * The setting of the internal template has not changed with the addition of
 * the list structures.  The internal template is still used to perform the
 * initial decoding of the data that arrives at the collector.
 *
 * Basic lists are not transcoded in the same way as templates because they
 * contain just one information element, thus having no order, so the data can
 * just be parsed and copied to a buffer.
 *
 * The question with decoding sub templates becomes, what do we use as an
 * internal template for any sub templates that arrive?  The answer is a new
 * structure in fixbuf that pairs external and internal template IDs for use
 * in decoding sub templates.  The pairs are added to the session that is used
 * for the connection, using fbSessionAddTemplatePair().
 *
 * Because the external template IDs are only unique for that session, the
 * collector must know the IDs of the templates that are collected in order to
 * pair an internal template with the external template.  As a result, callback
 * functionality has been added to fixbuf to alert the user when a new external
 * template has arrived.  The function to be called is stored in the session
 * structure, which manages the templates.  The callback gives the user a
 * pointer to the template structure which contains the information elements,
 * allowing the application to determine the contents of the template.  The
 * template ID used for this template, along with the session pointer is
 * enough for the application to successfully add template pairs to the
 * session for sub template decoding.
 *
 * If the application does not use the callback, or does not add any template
 * pairs to the session, then fixbuf will transcode each of the sub templates
 * as if the external and internal template were same.  This causes all of the
 * fields sent over the wire to be transcoded into the data buffer on the
 * collecting side.  The details of that template are passed up to the
 * collector upon receipt of data so it knows how the data is structured in
 * the buffer.
 *
 * If the application adds any template pair to the list, then the list will be
 * referenced for each transcode.  Any external template the application
 * wishes to process MUST have an entry in the list.
 * There are 3 cases for entries in the list:
 *   1. There is no entry for the given external template ID, so the entire
 *      sub template is ignored by the transcoder.
 *      The collector will be given a sub template list (or multi list entry)
 *      struct with the number of elements in the list set to 0, and the data
 *      pointer set to NULL.
 *   2. The listing exists, and the external and internal template IDs are set
 *      to the same value.  When decoding, the list of internal templates is
 *      queried to see if a template exists with the same ID as the external
 *      template. If not, the transcoder decodes each of the
 *      information elements, in the same order, into the buffer. This is a
 *      change as setting them equal to each other used to force a full decode.
 *      This change highlights the need for careful template ID management.
 *   3. The listing exists, and the external and internal template IDs are
 *      different.  This will transcode in the standard way external templates
 *      have been transcoded into internal templates, selecting the desired
 *      elements (listed in the internal template) from the data that arrived
 *      in the external template.
 *
 *
 *
 * @subsubsection iterating Iterating Over the Lists
 * There are four scenerios in which the user needs to iterate through the
 * elements in a list, whether to fill in, or process the data:
 *  1.  Iterating over the repeated information element data in a basic list
 *  2.  Iterating over the decoded data elements in a sub template list
 *  3.  Iterating over the entries that make up a sub template multi list
 *  4.  Iterating over the docoded data elements in an entry of a sub template
 *      multi list
 * The two iterating mechanisms are the same in each case:
 * Each of the function names start with the structure being iterated over,
 * e.g., fbBasicList, or fbSubTemplateMultiListEntry
 *  1.  Indexing
 *      The function used here is (structName)GetIndexed(dataPtr or entry)()
 *      It takes a pointer to the struct, and the index to be retrieved.
 *      Example usage:
 *          for(i = 0; myStructPtr = ...GetIndexedDataPtr(listPtr, i); i++) {
 *              process the data that myStructPtr points to.
 *          }
 *          The loop will end because when i is passed the bounds of the list
 *          the GetIndexedDataPtr() returns NULL.
 *
 *  2.  Incrementing
 *      The function used here is (structName)GetNext(dataPtr or entry)()
 *      It takes a pointer to the struct, and a pointer to an element in the
 *      list.  Pass in NULL at the beginning to get the first element back.
 *      Example usage:
 *          myStructPtr = NULL;
 *          while(myStructPtr = ...GetNextPtr(listPtr, myStructPtr)) {
 *              process the data that myStructPtr points to.
 *          }
 *          The loop will end because the function will return NULL when
 *          it gets passed the end of the list.  A key part here is
 *          initializing myStructPtr to NULL at the beginning!
 */

#ifndef _FB_PUBLIC_H_
#define _FB_PUBLIC_H_
#include <fixbuf/autoinc.h>

#ifdef __cplusplus
extern "C" {
#endif

#ident "$Id: public.h 18744 2013-03-07 17:48:39Z ecoff_svn $"

/*
 * Error Handling Definitions
 */

/** All fixbuf errors are returned within the FB_ERROR_DOMAIN domain. */
#define FB_ERROR_DOMAIN             g_quark_from_string("fixbufError")
/** No template was available for the given template ID. */
#define FB_ERROR_TMPL               1
/**
 * End of IPFIX message. Either there are no more records present in the
 * message on read, or the message MTU has been reached on write.
 */
#define FB_ERROR_EOM                2
/**
 * End of IPFIX Message stream. No more messages are available from the
 * transport layer on read, either because the session has closed, or the
 * file has been processed.
 */
#define FB_ERROR_EOF                3
/**
 * Illegal IPFIX mesaage content on read. The input stream is malformed, or
 * is not an IPFIX Message after all.
 */
#define FB_ERROR_IPFIX              4
/**
 * A message was received larger than the collector buffer size.
 * Should never occur. This condition is checked at the transport layer
 * in case future versions of fixbuf support dynamic buffer sizing.
 */
#define FB_ERROR_BUFSZ              5
/** The requested feature is not yet implemented. */
#define FB_ERROR_IMPL               6
/** An unspecified I/O error occured. */
#define FB_ERROR_IO                 7
/**
 * No data is available for reading from the transport layer.
 * Either a transport layer read was interrupted, or timed out.
 */
#define FB_ERROR_NLREAD             8
/**
 * An attempt to write data to the transport layer failed due to
 * closure of the remote end of the connection. Currently only occurs with
 * the TCP transport layer.
 */
#define FB_ERROR_NLWRITE            9
/**
 * The specified Information Element does not exist in the Information Model.
 */
#define FB_ERROR_NOELEMENT          10
/**
 * A connection or association could not be established or maintained.
 */
#define FB_ERROR_CONN               11
/**
 * Illegal NetflowV9 content on a read.  Can't parse the Netflow header or
 * the stream is not a NetflowV9 stream
 */
#define FB_ERROR_NETFLOWV9          12
/**
 * Miscellaneous error occured during translator operation
 */
#define FB_ERROR_TRANSMISC          13

/*
 * Public Datatypes and Constants
 */

struct fBuf_st;
/**
 * An IPFIX message buffer. Used to encode and decode records from
 * IPFIX Messages. The internals of this structure are private to
 * libfixbuf.
 */
typedef struct fBuf_st fBuf_t;

/**
 * A variable-length field value. Variable-length information element
 * content is represented by an fbVarfield_t on the internal side of the
 * transcoder; that is, variable length fields in an IPFIX Message must be
 * represented by this structure within the application record.
 */
typedef struct fbVarfield_st {
    /** Length of content in buffer. */
    size_t      len;
    /**
     * Content buffer. In network byte order as appropriate. On write, this
     * buffer will be copied into the message buffer. On read, this buffer
     * points into the message buffer and must be copied by the caller before
     * any call to fBufNext().
     */
    uint8_t     *buf;
} fbVarfield_t;


struct fbInfoModel_st;
/**
 * An IPFIX information model. Contains information element definitions.
 * The internals of this structure are private to libfixbuf.
 */
typedef struct fbInfoModel_st fbInfoModel_t;

/**
 * Convenience macro for creating fbInfoElement_t static initializers.
 * Used for creating information element arrays suitable for passing to
 * fbInfoModelAddElementArray().
 */
#define FB_IE_INIT(_name_, _ent_, _num_, _len_, _flags_) \
    {{(const struct fbInfoElement_st*)_name_}, 0, _ent_, _num_, _len_, _flags_}

/**
 * Convenience macro defining a null information element initializer to
 * terminate a constant information element array for passing to
 * fbInfoModelAddElementArray().
 */
#define FB_IE_NULL FB_IE_INIT(NULL, 0, 0, 0, 0)

/**
 * Default treatment flags value. Provided for initializer convenience.
 * Corresponds to octet-array semantics for a non-reversible, non-alien IE.
 */
#define FB_IE_F_NONE                            0x00000000

/**
 * Information element endian conversion flag. If set, IE is an integer and
 * will be endian-converted on transcode.
 */
#define FB_IE_F_ENDIAN                          0x00000001

/**
 * Information element reversible flag. If set for an information element
 * with an enterprise number of 0 (an IETF/IANA IE), adding the information
 * element via fbInfoModelAddElement() or fbInfoModelAddElementArray() will
 * cause a second, reverse information element to be added to the model
 * following the conventions in IETF Internet-Draft draft-ietf-ipfix-biflow-03.
 * Note that the reverse PEN has not yet been assigned, so this implementation
 * uses a provisional reverse IE as defined by the macro FB_IE_PEN_REVERSE.
 */
#define FB_IE_F_REVERSIBLE                      0x00000040

/**
 * Information element alien flag. If set, IE is enterprise-specific and was
 * recieved via an external template at a Collecting Process. It is therefore
 * subject to semantic typing via options (not yet implemented). Do not set this
 * flag on information elements added programmatically to an information model
 * via fbInfoModelAddElement() or fbInfoModelAddElementArray().
 */
#define FB_IE_F_ALIEN                           0x00000080

/**
 * Information element length constant for variable-length IE.
 */
#define FB_IE_VARLEN                            65535

/**
 * Information element number constant for basic lists
 * This will change upon updates to the specification.
 */
#define FB_IE_BASIC_LIST                        291
/**
 * Information element number constant for sub template lists
 * This will change upon updates to the IPFIX lists specification
 */
#define FB_IE_SUBTEMPLATE_LIST                  292
/**
 * Information element number constant for sub template multi lists
 * This will change upon updates to the IPFIX lists specification
*/
#define FB_IE_SUBTEMPLATE_MULTILIST             293

/**
 * Private enterprise number for reverse information elements
 * (see draft-ietf-ipfix-biflow-03 section 6.1).  If an information element with
 * FB_IE_F_REVERSIBLE and a zero enterprise number (i.e., an IANA-assigned
 * information element) is added to a model, the reverse IE will be generated
 * by setting the enterprise number to this constant.
 */
#define FB_IE_PEN_REVERSE                       29305

/**
 * Reverse information element bit for vendor-specific information elements
 * (see draft-ietf-ipfix-biflow-03 section 6.2). If an information element with
 * FB_IE_F_REVERSIBLE and a non-zero enterprise number (i.e., a vendor-specific
 * information element) is added to a model, the reverse IE number will be
 * generated by ORing this bit with the given forward information element
 * number.
 */
#define FB_IE_VENDOR_BIT_REVERSE                0x4000

/**
 * Generic Information Element ID for undefined Cisco NetFlow v9 Elements.
 *
 *
 */
#define FB_CISCO_GENERIC                       9999
/**
 * Information Element ID for Cisco NSEL Element NF_F_FW_EVENT often
 * exported by Cisco's ASA Device.  This must be converted to a different
 * Information Element ID due to the reverse IE bit in IPFIX.
 * Cisco uses IE ID 40005.
 * http://www.cisco.com/en/US/docs/security/asa/asa82/netflow/netflow.html
 */
#define FB_CISCO_ASA_EVENT_ID                  9998
/**
 * Information Element ID for Cisco NSEL Element NF_F_FW_EXT_EVENT often
 * exported by Cisco's ASA Device.  This must be converted to a different
 * Information Element ID due to the reverse IE bit in IPFIX.
 * Cisco uses IE ID 33002
 * http://www.cisco.com/en/US/docs/security/asa/asa82/netflow/netflow.html
 */
#define FB_CISCO_ASA_EVENT_XTRA                9997
/**
 * Reverse information element name prefix. This string is prepended to an
 * information element name, and the first character after this string
 * is capitalized, when generating a reverse information element.
 */
#define FB_IE_REVERSE_STR                       "reverse"

/** Length of reverse information element name prefix. */
#define FB_IE_REVERSE_STRLEN                    7

/**
 * A single IPFIX Information Element definition.
 * An Information Element defines the type of data in each field of
 * a record. This structure may be contained in an fbInfoModel_t,
 * in which case the name field contians the information element name,
 * or an an fbTemplate_t, in which case the canon field references the
 * fbInfoElement_t contained within the Information Model.
 */
typedef struct fbInfoElement_st {
    /** Information element name. */
    union {
        /**
         * Pointer to canonical copy of IE.
         * Set by fbInfoElementCopyToTemplate(),
         * and valid only for template IEs.
         */
        const struct fbInfoElement_st *canon;
        /**
         * Information element name. Storage for this is managed
         * by fbInfoModel. Valid only for model IEs.
         */
        const char                    *name;
    }  ref;

    /**
     * Multiple IE index. Must be 0 for model IEs.
     * Defines the ordering of identical IEs in templates.
     * Set and managed automatically by the fbTemplate_t routines.
     */
    uint32_t            midx;
    /** Private Enterprise Number. Set to 0 for IETF-defined IEs. */
    uint32_t            ent;
    /**
     * Information Element number. Does not include the on-wire
     * enterprise bit; i.e. num & 0x8000 == 0 even if ent > 0.
     */
    uint16_t            num;
    /** Information element length in octets. */
    uint16_t            len;
    /** Flags. Bitwise OR of FB_IE_F_* constants. */
    uint32_t            flags;
} fbInfoElement_t;

/**
 * Template ID argument to pass to fbSessionAddTemplate to automatically
 * assign a template ID.
 */
#define FB_TID_AUTO         0

/**
 * Reserved set ID for template sets.
 */
#define FB_TID_TS           2

/**
 * Reserved set ID for options template sets.
 */
#define FB_TID_OTS          3

/**
 * Minimum non-reserved template ID available for data sets.
 */
#define FB_TID_MIN_DATA     256

struct fbTemplate_st;
/**
 * An IPFIX Template or Options Template. Templates define the structure of
 * data records and options records within an IPFIX Message.
 * The internals of this structure are private to libfixbuf.
 */
typedef struct fbTemplate_st fbTemplate_t;

/**
 * Convenience macro defining a null information element specification
 * initializer to terminate a constant information element specifier array
 * for passing to fbTemplateAppendSpecArray().
 */
#define FB_IESPEC_NULL { NULL, 0, 0 }

/**
 * A single IPFIX Information Element specification.
 * Used to name an information element for inclusion in a template by
 * fbTemplateAppendSpecArray().
 */
typedef struct fbInfoElementSpec_st {
    /** Information element name */
    char                *name;
    /**
     * Length override; if nonzero, replace the length of the IE from the
     * model with this length. Used for reduced-length encoding.
     */
    uint16_t            len_override;
    /**
     * Application flags word. If nonzero, then the flags argument to
     * fbTemplateAppendSpec() or fbTemplateAppendSpecArray() MUST match at
     * least one bit of this flags word in order for the information element
     * to be appended.
     */
    uint32_t            flags;
} fbInfoElementSpec_t;

struct fbSession_st;
/**
 * An IPFIX Transport Session state container. Though Session creation and
 * lifetime are managed by the fbCollector_t and fbExporter_t types, each
 * fBuf_t buffer uses this type to store session state, including internal
 * and external Templates and Message Sequence Number information.
 */
typedef struct fbSession_st fbSession_t;

/** Transport protocol for connection specifier. */
typedef enum fbTransport_en {
    /**
     * Partially reliable datagram transport via SCTP.
     * Only available if fixbuf was built with SCTP support.
     */
    FB_SCTP,
    /** Reliable stream transport via TCP. */
    FB_TCP,
    /** Unreliable datagram transport via UDP. */
    FB_UDP,
    /**
     * Secure, partially reliable datagram transport via DTLS over SCTP.
     * Only available if fixbuf was built with OpenSSL support.
     * Requires an OpenSSL implementation of DLTS over SCTP, not yet available.
     */
    FB_DTLS_SCTP,
    /**
     * Secure, reliable stream transport via TLS over TCP.
     * Only available if fixbuf was built with OpenSSL support.
     */
    FB_TLS_TCP,
    /**
     * Secure, unreliable datagram transport via DTLS over UDP.
     * Only available if fixbuf was built with OpenSSL support.
     * Requires OpenSSL 0.9.8 or later with DTLS support.
     */
    FB_DTLS_UDP,
} fbTransport_t;

/**
 * Connection specifier. Used to define a peer address for fbExporter_t, or a
 * passive address for fbListener_t.
 */
typedef struct fbConnSpec_st {
    /** Transport protocol to use */
    fbTransport_t       transport;
    /** Hostname to connect/listen to. NULL to listen on all interfaces. */
    char                *host;
    /** Service name or port number to connect/listen to. */
    char                *svc;
    /** Path to certificate authority file. Only used for OpenSSL transport. */
    char                *ssl_ca_file;
    /** Path to certificate file. Only used for OpenSSL transport. */
    char                *ssl_cert_file;
    /** Path to private key file. Only used for OpenSSL transport. */
    char                *ssl_key_file;
    /** Private key decryption password. Only used for OpenSSL transport. */
    char                *ssl_key_pass;
    /**
     * Pointer to address info cache. Initialize to NULL.
     * For fixbuf internal use only.
     */
    void                *vai;
    /**
     * Pointer to SSL context cache. Initialize to NULL.
     * For fixbuf internal use only.
     */
    void                *vssl_ctx;
} fbConnSpec_t;

/**
 * Convenience macro defining a null static fbConnSpec_t.
 */
#define FB_CONNSPEC_INIT { FB_SCTP, NULL, NULL,         \
                           NULL, NULL, NULL, NULL,      \
                           NULL, NULL }

#if HAVE_SPREAD
/**
 * Spread connection parameters. Used to define a spread daemon and group
 * or list of groups for spread.
 */

#define FB_SPREADPARAMS_INIT { 0, 0, 0 }

typedef struct fbSpreadParams_st {
    /** pointer to the session, this MUST be set to a valid session before
    *   the spec is passed to fbExporterAllocSpread. */
    fbSession_t * session;
    /** pointer to the daemon host address, in Spread format.  Must be set
    *   before the spec is passed to fbExporterAllocSpread */
    char *          daemon;
    /** pointer to array of group names, must have at least one, and must
    *   be null term array */
    char **         groups;
} fbSpreadParams_t;

#endif /* HAVE_SPREAD */

struct fbExporter_st;
/**
 * IPFIX Exporting Process endpoint. Used to export messages from an associated
 * IPFIX Message Buffer to a remote Collecting Process, or to an IPFIX File.
 * The internals of this structure are private to libfixbuf.
 */
typedef struct fbExporter_st fbExporter_t;

struct fbCollector_st;
/**
 * IPFIX Collecting Process endpoint. Used to collect messages into an
 * associated IPFIX Message Buffer from a remote Exporting Process, or from
 * an IPFIX File. Use this with the fbListener_t structure to implement a full
 * Collecting Process, including Transport Session setup. The internals of
 * this structure are private to libfixbuf.
 */
typedef struct fbCollector_st fbCollector_t;

struct fbListener_st;
/**
 * IPFIX Collecting Process session listener. Used to wait for connections
 * from IPFIX Exporting Processes, and to manage open connections via a
 * select(2)-based mechanism. The internals of this structure are private
 * to libfixbuf.
 */
typedef struct fbListener_st fbListener_t;

/**
 *  ListenerGroup and associated data type definitions
 */
typedef struct fbListenerEntry_st fbListenerEntry_t;

/**
 *  ListenerEntry's make up a listener group as a linked list
 */
struct fbListenerEntry_st
{
    /** pointer to the next listener entry in the linked list */
    fbListenerEntry_t  *next;
    /** pointer to the previous listener entry in the linked list */
    fbListenerEntry_t  *prev;
    /** pointer to the listener to add to the list */
    fbListener_t       *listener;
};

/**
 * typedef for listener group result
 */
typedef struct fbListenerGroupResult_st fbListenerGroupResult_t;

/**
 * ListenerGroupResult's contain the listener who's listening socket got a new
 * connection.  It is tied to the fBuf_t that is produced for the connection
 * These make up a linked list as well
 */
struct fbListenerGroupResult_st
{
    /** Pointer to the next listener group result */
    fbListenerGroupResult_t *next;
    /** pointer to the listener that received a new connection */
    fbListener_t    *listener;
    /** pointer to the fbuf created for that new connection */
    fBuf_t          *fbuf;
};

/**
 * Structure that holds the listeners that are added to the group.
 */
typedef struct fbListenerGroup_st
{
    /** pointer to the head of the listener group result list */
    fbListenerEntry_t   *head;
    /** pointer to a generic structure for future use */
    void                *tableForDescriptorsToListeners;
} fbListenerGroup_t;

/**
 * the callback function to be called when a new connection to a listener
 * has been received.
 * The memory pointed to by buf and listener will not be cleared so copies
 * of that memory do not need to be done in this function, just copies of the
 * pointers themselves will need to be retained.
 * @param buf pointer to the new buffer created for the new collector
 * @param listener pointer to the listener that received the connection
 * @param sAddr sockaddr struct describing the connecting node
 * @param err error buffer containing error string
 * @return TRUE is the callback succeeds, FALSE on error
 */
typedef gboolean (*fbAcceptCallback_fn) (
    fBuf_t                     *buf,
    fbListener_t               *listener,
    struct sockaddr            *sAddr,
    GError                    **err);

/**
 * The callback function to be called when the session receives a new
 * external template from the connected node.
 * The point of this callback is to be able to assign an internal template
 * to a received external template for subTemplates
 * @param session a pointer to the session that received the template
 * @param tid the template ID for the template that was received
 * @param tmpl pointer to the template information of the received template
 * @return NO return value
 */
typedef void (*fbNewTemplateCallback_fn) (
    fbSession_t    *session,
    uint16_t        tid,
    fbTemplate_t   *tmpl);

/**
 * Semantic field indicating the value has not been set
 */
#define UNDEFINED       0xFF
/**
 * Semantic field for none-of value defined in the spec
 */
#define NONE_OF         0x00
/**
 * Semantic field for exactly-one-of value defined in the spec
 */
#define EXACTLY_ONE_OF  0x01
/**
 * Semantic field for the one-or-more-of value defined in the spec
 */
#define ONE_OR_MORE_OF  0x02
/**
 * Semantic field for the all-of value defined in the spec
 */
#define ALL_OF          0x03
/**
 * Semantic field for the ordered value defined in the spec
 */
#define ORDERED         0x04

/**
 *   validates the value of the semantic field,
 *
 * @param semantic The value of the semantic field to be validated  *
 * @return TRUE is valid {0xFF, 0x00-0x04}, FALSE if not
 */
gboolean fbListValidSemantic(
    uint8_t semantic);

/****** BASICLIST FUNCTIONS AND STRUCTS *******/
/**
 * A basic list element in a template which structure represents a
 * basic list on the internal side, basic lists in an IPFIX Message must
 * be represented by this structure within the application record.
 */
typedef struct fbBasicList_st {
    /** pointer to the information element that is repeated in the list */
    const fbInfoElement_t   *infoElement;
    /** pointer to the memory that stores the elements in the list */
    uint8_t                 *dataPtr;
    /** number of elements in the list */
    uint16_t                numElements;
    /** length of the buffer used to store the elements in the list */
    uint16_t                dataLength;
    /** semantic field to describe the list */
    uint8_t                 semantic;
} fbBasicList_t;


/**
 *  allocates a Basic List Structure
 *
 * @return a pointer a to the allocated basic list in memory
 */
fbBasicList_t*  fbBasicListAlloc(
    void);

/**
 * Initializes the basic list structure based on the parameters.
 * This function allocates a buffer large enough to hold
 * num elements amount of the infoElements.
 *
 * @param basicListPtr a pointer to the basic list structure to fill
 * @param semantic the semantic value to be used in the basic list
 * @param infoElement a pointer to the info element to be used in the list
 * @param numElements number of elements in the list
 * @return a pointer to the memory where the list data is to be written
 */

void* fbBasicListInit(
    fbBasicList_t          *basicListPtr,
    uint8_t                 semantic,
    const fbInfoElement_t  *infoElement,
    uint16_t                numElements);

/**
 *  use this function to initialize the basic list, but it gets the pointer
 *  to a buffer and its length allocated independently from these functions
 *  This will generally be used by a collector that does not want to
 *  free and allocate new buffers for each incoming message
 *
 * @param basicListPtr a pointer to the basic list structure to fill
 * @param semantic the semantic value to be used in the basic list
 * @param infoElement a pointer to the info element to be used in the list
 * @param numElements number of elements in the list
 * @param dataLength length of the buffer passed to the function
 * @param dataPtr pointer to the buffer previously allocated for the list
 * @return a pointer to the beginning of the buffer on success, NULL on failure
 */
void* fbBasicListInitWithOwnBuffer(
    fbBasicList_t          *basicListPtr,
    uint8_t                 semantic,
    const fbInfoElement_t  *infoElement,
    uint16_t                numElements,
    uint16_t                dataLength,
    uint8_t                *dataPtr);

/**
 *   This initializes a basic list structure for collection.  The key
 *   part of this function is it sets the dataPtr to NULL.
 *   If your basic list is declared as a pointer, then allocated using
 *   something like g_slice_alloc0 which sets it all to zero, you do not
 *   need to call this function.  But if your basic list struct isn't
 *   a pointer, there dataPtr parameter will be set to garbage, which will
 *   break other fixbuf calls, so this function is required
 *
 * @param basicListPtr pointer to the basic list to be initialized
 * @return NONE
 */
void fbBasicListCollectorInit(
    fbBasicList_t  *basicListPtr);


/**
 *  Get Semantic field for Basic List
 *  presumably used in collectors after decoding
 *
 *  @param basicListPtr pointer to the basic list to retrieve the semantic from
 *  @return the 8-bit semantic value describing the basic list
 */
uint8_t fbBasicListGetSemantic(
    fbBasicList_t  *basicListPtr);

/**
 *  Sets the semantic for describing a basic list
 *  generally used in exporters before decoding
 *
 *  @param basicListPtr pointer to the basic list to set the semantic
 *  @param semantic value to set the semantic field to
 *  @return NONE
 */
void fbBasicListSetSemantic(
    fbBasicList_t  *basicListPtr,
    uint8_t         semantic);


/**
 * This function returns a pointer to the information element used in the list
 * it is mainly used in collectors to retrieve information
 *
 * @param basicListPtr pointer to the basic list to get the infoElement from
 * @return pointer to the information element from the list
 */
const fbInfoElement_t*  fbBasicListGetInfoElement(
     fbBasicList_t  *basicListPtr);

/**
 *
 * @param basicListPtr pointer to the basic list to get the data pointer from
 * @return the pointer to the data held by the basic list
 */
void* fbBasicListGetDataPtr(
    fbBasicList_t   *basicListPtr);

/**
 * Function retrieves the index'th element in the list
 * index is 0-based.  Goes from 0 - (numElements-1)
 * @param basicListPtr pointer to the basic list to retrieve the dataPtr
 * @param bl_index the index of the element to retrieve
 * @return a pointer to the data in the index'th slot in the list, NULL
 * if the index is past the bounds of the list
 */
void* fbBasicListGetIndexedDataPtr(
    fbBasicList_t   *basicListPtr,
    uint16_t         bl_index);

/**
 * Function returns the next element in the list based on the currentPtr
 * @param basicListPtr pointer to the basic list
 * @param currentPtr pointer to the current element being used.  Set to NULL
 * to retrieve the first element.
 * @return a pointer to the next data slot, based on the current pointer.
 * NULL if the new pointer is passed the end of the buffer
 */
void* fbBasicListGetNextPtr(
    fbBasicList_t   *basicListPtr,
    void            *currentPtr);

/**
 * Free the current data pointer, allocating a new buffer to accomodate
 * the new number of elements.  The remaining parameters are unchanged.
 * If the number of elements hasn't changed
 * the original buffer is used and its pointer is returned
 * @param basicList pointer to the basic list to realloc
 * @param newNumElements new number of elements to allocate for the list
 * @return pointer to the data pointer for the list after realloc
 */
void* fbBasicListRealloc(
    fbBasicList_t  *basicList,
    uint16_t        newNumElements);

/**
 *  Allocates an additional elememnt into the basic list
 *  must be called after calling BasicListInit
 * @param basicList pointer to the basic list to add elements to
 * @param numNewElements number of elements to add to the list
 * @return a pointer to the newly allocated element(s)
*/
void* fbBasicListAddNewElements(
    fbBasicList_t  *basicList,
    uint16_t        numNewElements);

/**
 * Clear the parameters of the basic list and free the data buffer
 * @param basicListPtr pointer to the basic list to clear
 * @return NONE
 */
void fbBasicListClear(
    fbBasicList_t  *basicListPtr);

/**
 * Clear the parameters of the basic list, but do not free the buffer.
 * This should get used when the user provides their own buffer
 * @param basicList pointer to the basic list to clear without freeing
 * @return NONE
 */
void fbBasicListClearWithoutFree(
    fbBasicList_t  *basicList);

/**
 * Clear the basic list, then free the basic list pointer
 * @param basicListPtr pointer to the basic list to free
 * @return NONE
 */
void fbBasicListFree(
    fbBasicList_t  *basicListPtr);

/******* END OF BASICLIST ********/



/******* SUBTEMPLATELIST FUNCTIONS ****/

/**
 * Structure used to hold information of a sub template list.
 * This structure is filled in by the user in an exporter to tell
 * fixbuf how to encode the data.
 * This structure is filled in by the transcoder in a collector,
 * feeding the useful information up to the user
 */
typedef struct fbSubTemplateList_st {
    /** length of the allocated buffer used to hold the data */
    /** I made this a union to allow this to work on 64-bit archs */
    union {
        size_t          length;
        uint64_t        extra;
    } dataLength;
    /** pointer to the template used to structure the data */
    const fbTemplate_t  *tmpl;
    /** pointer to the buffer used to hold the data */
    uint8_t             *dataPtr;
    /** ID of the template used to structure the data */
    uint16_t            tmplID;
    /** number of elements in the list */
    uint16_t            numElements;
    /** value used to describe the contents of the list, all-of, one-of, etc*/
    uint8_t             semantic;
} fbSubTemplateList_t;

/**
 *  Allocates a subTemplateList_t
 *  Based on how subTemplateLists will be used and set up amidst data
 *  structures, this function may never be used
 * @return pointer to the new sub template list
 */
fbSubTemplateList_t* fbSubTemplateListAlloc(
    void);

/**
 *  Initializes a subTemplateList structure and alloc's the dataPtr
 *  to get a buffer able to hold numElements in the template
 *  This will mainly be used in exporters preparing to encode
 *
 * @param sTL pointer to the sub template list to initialize
 * @param semantic the semantic value used to describe the list contents
 * @param tmplID id of the template used for encoding the list data
 * @param tmpl pointer to the template struct used for encoding the list data
 * @param numElements number of elements in the list
 * @return a pointer to the allocated buffer (location of first element)
 */
void*  fbSubTemplateListInit(
    fbSubTemplateList_t    *sTL,
    uint8_t                 semantic,
    uint16_t                tmplID,
    const fbTemplate_t     *tmpl,
    uint16_t                numElements);

/**
 *  Initializes the subTemplateList but does not allocate a buffer.  It
 *  accepts a previously allocated buffer and data length and uses it.
 *  This will generally be used in collectors providing their own buffer
 *
 * @param subTemplateList pointer to the sub template list to initialize
 * @param semantic the semantic value used to describe the list contents
 * @param tmplID id of the template used for encoding the list data
 * @param tmpl pointer to the template struct used for encoding the list data
 * @param numElements number of elements in the list
 * @param dataLength length of the data buffer
 * @param dataPtr pointer to the previously allocated data buffer
 * @returns a pointer to that buffer
*/
void* fbSubTemplateListInitWithOwnBuffer(
    fbSubTemplateList_t    *subTemplateList,
    uint8_t                 semantic,
    uint16_t                tmplID,
    const fbTemplate_t     *tmpl,
    uint16_t                numElements,
    uint16_t                dataLength,
    uint8_t                *dataPtr);

/**
 * Initializes a sub template list variable on a collector.  If the
 * fbSubTemplateList variable is in a struct, it will likely not be set to 0's
 * If not, the dataPtr will not be NULL, so the transcoder will not allocate
 * the right memory for it, as it will assuming it's set up.  This will break.
 * Call this function right after declaring the struct variable that contains
 * the fbSubTemplateList.  It only needs to be called once for each STL
 * @param STL pointer to the sub template list to initialize for collection
 * @return NONE
 */
void fbSubTemplateListCollectorInit(
    fbSubTemplateList_t    *STL);

/**
 * Returns a pointer to the buffer that contains the data for the list
 * @param subTemplateListPtr pointer to the STL to get the pointer from
 * @return a pointer to the data buffer used by the sub template list
 */
void* fbSubTemplateListGetDataPtr(
    const fbSubTemplateList_t  *subTemplateListPtr);

/**
 * This function is used to iterate over the elements in the list by
 * passing in a counter to indicate which element is to be returned
 * @param subTemplateListPtr pointer to the STL
 * @param index The index of the element to be retrieved (0-based)
 * @return a pointer to the desired element.  NULL if index >= numElements
 */
void* fbSubTemplateListGetIndexedDataPtr(
    const fbSubTemplateList_t  *subTemplateListPtr,
    uint16_t                    index);

/**
 * This function also traverses the elements in the list by accepting
 * a pointer to the last element the user accessed, moves it to the next
 * element and returns a pointer to the next element.  A current element of
 * NULL tells the function to return the first element in the list.
 * @param subTemplateListPtr pointer to the STL to get data from
 * @param currentPtr pointer to the last element accessed.  NULL causes the
 *                   pointer to the first element to be returned
 * @return the pointer to the next element in the list.  Returns NULL if
 *         currentPtr points to the last element in the list.
 */
void* fbSubTemplateListGetNextPtr(
    const fbSubTemplateList_t  *subTemplateListPtr,
    void                       *currentPtr);

/**
 * Sets the semantic parameter of a subTemplateList
 * @param subTemplateListPtr pointer to the sub template list
 * @param semantic Semantic value for the list
 * @return NONE
 */
void fbSubTemplateListSetSemantic(
    fbSubTemplateList_t    *subTemplateListPtr,
    uint8_t                 semantic);

/**
 * Gets the semantic value from a sub template list
 * @param subTemplateListPtr pointer to the sub template list
 * @return the semantic field from the list
 */
uint8_t fbSubTemplateListGetSemantic(
    fbSubTemplateList_t    *subTemplateListPtr);

/**
 * Gets the template pointer from the list structure
 * @param subTemplateListPtr pointer to the sub template list
 * @return a pointer to the template used by the sub template list
 */
const fbTemplate_t* fbSubTemplateListGetTemplate(
    fbSubTemplateList_t    *subTemplateListPtr);

/**
 * Gets the template ID for the template used by the list
 * @param subTemplateListPtr pointer to the sub template list
 * @return the template ID used by the sub template list
 */
uint16_t fbSubTemplateListGetTemplateID(
    fbSubTemplateList_t    *subTemplateListPtr);

/**
 *  Free the current data pointer, allocating a new buffer to accomodate
 *  the new number of elements.  The remaining parameters are unchanged.
 *  If the number of elements hasn't changed
 *  the original buffer is used and its pointer is returned
 *
 * @param subTemplateList pointer to the sub template list to realloc
 * @param newNumElements value for the new number of elements for the list
 * @return pointer to the data buffer after realloc
 */
void* fbSubTemplateListRealloc(
    fbSubTemplateList_t    *subTemplateList,
    uint16_t                newNumElements);

/**
 *  Allocates space for a number of additional element in the sub template list
 *  must be called after the list has been fbSubTemplateListInit()'d
 *
 * @param subTemplateList pointer to the sub template list
 * @param numNewElements number of new elements to add to the list
 * @return a pointer to the first newly allocated element
 */
void* fbSubTemplateListAddNewElements(
    fbSubTemplateList_t    *subTemplateList,
    uint16_t                numNewElements);

/**
 *  Clears a subtemplate list struct, notably freeing the dataPtr and setting
 *  it to NULL.
 *  This should be used after each call to fBufNext:
 *  If the dataPtr is not NULL in DecodeSubTemplateList, it will not allocate
 *  new memory for the new record, which could cause a buffer overflow if the
 *  new record has a longer list than the current one.
 *  An alternative is to allocate a large buffer and assign it to dataPtr
 *  on your own, then never clear it with this.  Be certain this buffer is
 *  longer than needed for all possible lists
 * @param subTemplateListPtr pointer to the sub template list to clear
 * @return NONE
 */
void fbSubTemplateListClear(
    fbSubTemplateList_t    *subTemplateListPtr);

/**
 *  Clears the sub template list parameters but does not free the data ptr.
 *  This is used in conjuction with STLInitOwnBuffer because that buffer
 *  is allocated at the beginning by the user and will be freed at the end
 *  by the user, outside of fixbuf api calls
 * @param subTemplateListPtr pointer to the sub template list to clear
 * @return NONE
*/
void fbSubTemplateListClearWithoutFree(
    fbSubTemplateList_t    *subTemplateListPtr);

/**
 *  Frees and clears a subTemplateList struct.  This frees the dataPtr AND
 *  frees the memory pointed to by the subTemplateListPtr
 * Used in conjunction with subTemplateListAlloc(), unlikely to be used
 * @param subTemplateListPtr pointer to the sub template list to free
 * @return NONE
 */
void fbSubTemplateListFree(
    fbSubTemplateList_t    *subTemplateListPtr);

/********* END OF SUBTEMPLATELIST **********/
/**
 *  Entries contain the same type of information at SubTemplateLists:
 *  template ID and template pointers to describe the data
 *  the number of data elements and the data pointer and data length
 *
 * Sub template multi lists are inherently nested constructions.
 * At a high level, they are a list of sub template lists.
 * The first level is a list of fbSubTemplateMultiListEntry_t's, which each
 * contain the information that describes the data contained in them.
 * Initializing a fbSubTemplateMultiList_t with a semantic and number of
 * elements returns memory that contains numElements blocks of memory
 * containing fbSubTemplateMultiListEntry_t's.  It is not ready to accept
 * data.  Each of the fbSubTemplateMultiListEntry_t's needed to be set up
 * then data is copied into the entries.
 */


typedef struct fbSubTemplateMultiListEntry_st {
    /** pointer to the template used to structure the data in this entry */
    fbTemplate_t   *tmpl;
    /** pointer to the buffer used to hold the data in this entry */
    uint8_t        *dataPtr;
    /** length of the buffer used to hold the data in this entry */
    size_t          dataLength;
    /** ID of the template used to structure the data in this entry */
    uint16_t        tmplID;
    /** number of elements in this entry */
    uint16_t        numElements;
} fbSubTemplateMultiListEntry_t;

/**
 * Multilists just contain the semantic to describe the sub lists,
 * the number of sub lists, and a pointer to the first entry
*/
typedef struct fbSubTemplateMultiList_st {
    /** pointer to the first entry in the multi list */
    fbSubTemplateMultiListEntry_t  *firstEntry;
    /** number of sub template lists in the multi list */
    uint16_t                        numElements;
    /** value used to describe the list of sub templates */
    uint8_t                         semantic;
} fbSubTemplateMultiList_t;

/**
 *  Initializes the multi list with semantic, numbers of elements,
 *  and allocates memory to store numElements worth of entries
 *
 * @param STML pointer to the sub template multi list to initialize
 * @param semantic value used to describe the entries in the multi list
 * @param numElements number of entries in the multi list
 * @return pointer to the first uninitialized entry
 */
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListInit(
    fbSubTemplateMultiList_t   *STML,
    uint8_t                     semantic,
    uint16_t                    numElements);

/**
 * Sets the semantic field for the multi list
 * @param STML pointer to the sub template multi list
 * @param semantic Value for the semantic field of the sub template multi list
 * @return NONE
*/
void fbSubTemplateMultiListSetSemantic(
    fbSubTemplateMultiList_t   *STML,
    uint8_t                     semantic);

/**
 * Get the semantic paramter from the multi list
 * @param STML pointer to the sub template multi list
 * @return semantic parameter describing the contents of the multi list
 */
uint8_t fbSubTemplateMultiListGetSemantic(
    fbSubTemplateMultiList_t   *STML);

/**
 *  Clears all of the entries (frees their data pointers), then frees the
 *  memory containing the entries
 * @param STML pointer to the sub template mutli list to clear
 * @return NONE
 */
void fbSubTemplateMultiListClear(
    fbSubTemplateMultiList_t   *STML);

/**
 * Clears the memory used by the entries of a sub template multi list
 * NOTE: if any of those entries contain another layer of structures, that
 * second layer must be freed by the user, this function cannot do that.
 * example: an entry's template contains an element of type basicList.  The
 * memory used by that basicList isn't freed by this function
 * @param STML pointer to the sub template multi list
 * @return NONE
 */
void fbSubTemplateMultiListClearEntries(
    fbSubTemplateMultiList_t   *STML);

/**
 * Clears the multi list, then frees the memory pointed to by STML
 * @param STML pointer to the sub template multi list
 * @return NONE
 */
void fbSubTemplateMultiListFree(
    fbSubTemplateMultiList_t   *STML);

/**
 *  Clears the entries used by the multi list, then if newNumElements
 *  is different than numElements, frees the entries buffer and allocates
 *  a new one.
 *
 * @param STML pointer to the sub template mutli list
 * @param newNumEntries the new number of entries for the STML
 * @return pointer to the first entry
*/
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListRealloc(
    fbSubTemplateMultiList_t   *STML,
    uint16_t                    newNumEntries);

/**
 *  Adds entries to the multi list of entries
 *  can only be run after the list has been initialized
 *
 * @param STML pointer to the sub template multi list
 * @param numNewEntries number of entries to add to the list
 * @return a pointer to the new entry
 */
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListAddNewEntries(
    fbSubTemplateMultiList_t   *STML,
    uint16_t                    numNewEntries);

/**
 * Retrieve the first entry in the multi list
 * @param STML pointer to the sub template multi list
 * @return pointer to the first entry used by the list
 */
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListGetFirstEntry(
    fbSubTemplateMultiList_t   *STML);

/**
 * Retrieve a pointer to the entry of a specific index.  The entry indexes
 * are zero based.  NULL is returned if the index requested is too high
 * @param STML pointer to the sub template mutli list
 * @param index index of the entry to be returned
 * @return the index'th entry used by the list.  NULL If index >= numElements
 */
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListGetIndexedEntry(
    fbSubTemplateMultiList_t   *STML,
    uint16_t                    index);

/**
 * This function also traverses the elements in the list by accepting
 * a pointer to the last element the user accessed, moves it to the next
 * element and returns a pointer to the next element.  A current element of
 * NULL tells the function to return the first element in the list.
 * @param STML pointer to the sub template multi list to get data from
 * @param currentEntry pointer to the last element accessed.
 *                     NULL means none have been accessed yet
 * @return the pointer to the next element in the list.  Returns the NULL
 *         if currentEntry points to the last entry.
 */
fbSubTemplateMultiListEntry_t* fbSubTemplateMultiListGetNextEntry(
    fbSubTemplateMultiList_t       *STML,
    fbSubTemplateMultiListEntry_t  *currentEntry);

/**
 *  Initializes the multi list entry with the template values,
 *  and allocates the memory used by the entry to hold the data.
 *
 *  @param entry pointer to the entry to initialize
 *  @param tmplID ID of the template used to structure the data elements
 *  @param tmpl pointer to the template used to structure the data elements
 *  @param numElements number of data elements in the entry
 *
 *  @return pointer to the data buffer to be filled in
*/
void* fbSubTemplateMultiListEntryInit(
    fbSubTemplateMultiListEntry_t  *entry,
    uint16_t                        tmplID,
    fbTemplate_t                   *tmpl,
    uint16_t                        numElements);

/**
 *  Frees the memory for the data used by the entry, then allocates
 *  a new buffer based on the size of the template and newNumElements.
 *  (if numElements doesn't change, the pointer is returned without freeing
 *  and allocating)
 *
 *  @param entry pointer to the entry to realloc
 *  @param newNumElements the new number of elements for the entry
 *  @return pointer to buffer to write data to
 */
void *fbSubTemplateMultiListEntryRealloc(
    fbSubTemplateMultiListEntry_t  *entry,
    uint16_t                        newNumElements);

/**
 *  Frees the memory pointed to by the data buffer holding the data elements
 *
 *  @param entry pointer to the entry to clear the contents of.
 *  @return NONE
 */
void fbSubTemplateMultiListEntryClear(
    fbSubTemplateMultiListEntry_t   *entry);

/**
 * Retrieves the data pointer for this entry
 *
 * @param entry pointer to the entry to get the data pointer from
 * @return pointer to the buffer used to store data for this entry
 */
void* fbSubTemplateMultiListEntryGetDataPtr(
    fbSubTemplateMultiListEntry_t   *entry);

/**
 * This function traverses the elements in the entry by accepting
 * a pointer to the last element the user accessed, moves it to the next
 * element and returns a pointer to the next element.  A current element of
 * NULL tells the function to return the first element in the list.
 * @param entry pointer to the entry to get the next element from
 * @param currentPtr pointer to the last element accessed.  NULL means return
                     a pointer to the first element.
 * @return the pointer to the next element in the list.  Returns NULL if
 *         currentPtr points to the last element in the list
 */
void* fbSubTemplateMultiListEntryNextDataPtr(
    fbSubTemplateMultiListEntry_t   *entry,
    void                            *currentPtr);

/**
 * Returns a pointer to a data element in the entry based on the index.
 * If the index is >= to the number of elements in the list, NULL is returned.
 * The elements are 0-based, so index = 0 is returns the first elements.
 *
 * @param entry pointer to the entry to get a data pointer from.
 * @param index the number of the element in the list to return
 * @return the pointer to the index'th element used by the entry
 *         NULL if the index is >= numElements
 */
void* fbSubTemplateMultiListEntryGetIndexedPtr(
    fbSubTemplateMultiListEntry_t   *entry,
    uint16_t                         index);

/**
 * Retrieve the template pointer used to structure the data elements
 *
 * @param entry pointer to the entry to get the template from
 * @return the template pointer used to describe the contents of the entry
 */
const fbTemplate_t* fbSubTemplateMultiListEntryGetTemplate(
    fbSubTemplateMultiListEntry_t   *entry);

/**
 * Retrieve the template ID for the template used to structure the data
 *
 * @param entry pointer to the entry to get the template ID from
 * @returns the template ID for template that describes the data
 */
uint16_t fbSubTemplateMultiListEntryGetTemplateID(
    fbSubTemplateMultiListEntry_t   *entry);

/************** END OF STML FUNCTIONS */

/**
 * Allocates and returns a fbListenerGroup with no entries
 *
 * @return a pointer to the created fbListenerGroup_t, or NULL on error
 */
fbListenerGroup_t* fbListenerGroupAlloc(
    void);

/**
 * Adds a previously allocated listener to the previously allocated group.
 * The listener is placed at the head of the list
 *
 * @param group pointer to the allocated group to add the listener to
 * @param listener pointer to the listener structure to add to the group
 * @return 0 upon success. "1" if entry couldn't be allocated
 *         "2" if either of the incoming pointers are NULL
 */
int fbListenerGroupAddListener(
    fbListenerGroup_t          *group,
    const fbListener_t         *listener);

/**
 * Removes the listener from the group.
 * IT DOES NOT FREE THE LISTENER OR THE GROUP
 *
 * @param group pointer to the group to remove from the listener from
 * @param listener pointer to the listener to remove from the group
 * @return 0 on success, and "1" if the listener is not found
 *         "2" if either of the pointers are NULL
 */
int fbListenerGroupDeleteListener(
    fbListenerGroup_t          *group,
    const fbListener_t         *listener);

/**
 *  Similar to fbListenerWait, except that is looks for connections for
 *  multiple listeners.  It takes a previously allocated and filled
 *  listener group.  It returns a pointer to the head of a list of
 *  listenerGroupResults.
 *  @param group pointer to the group of listeners to wait on
 *  @param err error string structure seen throughout fixbuf
 *  @return pointer to the head of the listener group result list
 *          NULL on error, and sets the error string
 */
fbListenerGroupResult_t* fbListenerGroupWait(
    fbListenerGroup_t          *group,
    GError                     **err);

/**
 *  Takes one listener, and instead of returning the fBuf created from the new
 *  collector, like fbListenerWait(), it calls the callback function provided.
 *
 *  @param listener listenr to wait on
 *  @param callback function to call upon receiving a new connection
 *  @param err standard fixbuf err string structure
 *  @return the boolean result of the callback, or FALSE plus the error string
 *          upon failure.
 */
gboolean fbListenerWaitAcceptCallback(
    fbListener_t           *listener,
    fbAcceptCallback_fn     callback,
    GError                **err);

/**
 *  A combination of ListenerGroupWait and ListenerWaitAcceptCallback.
 *  It monitors the list of listeners in the group, and calls the callback
 *  if any of them find a new connection.
 *
 *  @param group pointer to the group to wait for connections on
 *  @param callback function to call when a listener in the group gets a new
 *                  connection
 *  @param err standard error string structure in fixbuf
 *  @return a boolean AND of the results of each of the callbacks
 */

gboolean fbListenerGroupWaitAcceptCallback(
    fbListenerGroup_t   *group,
    fbAcceptCallback_fn  callback,
    GError             **err);

/**
 *  Returns an fBuf wrapped around an independently managed socket and a
 *  properly created listener for TCP connections.
 *  The caller is only responsible for creating the socket.
 *  The existing collector code will close the socket and cleanup everything.
 *
 *  @param listener pointer to the listener to wrap around the socket
 *  @param sock the socket descriptor of the independently managed socket
 *  @param err standard fixbuf err structure pointer
 *  @return pointer to the fbuf for the collector.
 *          NULL if sock is 0, 1, or 2 (stdin, stdout, or stderr)
 */
fBuf_t  *fbListenerOwnSocketCollectorTCP(
    fbListener_t   *listener,
    int             sock,
    GError        **err);

/**
 *  Same as fbListenerOwnSocketCollectorTCP but for TLS (not tested)
 *
 *  @param listener pointer to the listener to wait on
 *  @param sock independently managed socket descriptor
 *  @param err standard fixbuf err structure pointer
 *  @return pointer to the fbuf for the collector
 *          NULL if sock is 0, 1, or 2 (stdin, stdout, or stderr)
 */
fBuf_t  *fbListenerOwnSocketCollectorTLS(
    fbListener_t   *listener,
    int             sock,
    GError        **err);

/**
 *  Interrupts the select call of a specific collector by way of its fBuf.
 *  This is mainly used by fbListenerInterrupt to interrupt all of the
 *  collector sockets well.
 */
void    fBufInterruptSocket(
    fBuf_t         *fbuf);


/**
 * Application context initialization function type for fbListener_t.
 * This function is called after accept(2) for TCP or SCTP with the peer
 * address in the peer argument. For UDP, it is called during fbListener_t
 * initialization and the peer address will be NULL.  If the Collector is in
 * multi-session mode, the appinit function will be called when a new UDP
 * connection occurs with the peer address, similiar to the TCP case.  Use
 * fbCollectorSetUDPMultiSession() to turn on multi-session mode
 * (off by default).  The application may veto fbCollector_t creation by
 * returning FALSE. In multi-session mode, if the connection is to be ignored,
 * the application should set error code FB_ERROR_NLREAD on the err and return
 * FALSE.  If the application returns FALSE, fixbuf will maintain information
 * about that peer, and will reject connections from that peer until shutdown
 * or until that session times out.  Fixbuf will return FB_ERROR_NLREAD for
 * previously rejected sessions.
 * The context (returned via out-parameter ctx) will be
 * stored in the fbCollector_t, and is retrievable via a call to
 * fbCollectorGetContext().  If not in multi-session mode and using the appinit
 * fn, the ctx will be associated with all UDP sessions.
 */
typedef gboolean        (*fbListenerAppInit_fn) (
    fbListener_t                *listener,
    void                        **ctx,
    int                         fd,
    struct sockaddr             *peer,
    size_t                      peerlen,
    GError                      **err);

/**
 * Application context free function type for fbListener_t.
 * If the Collector is in multi-session mode (see appinit fn), then the
 * appfree function will be called if a session is timed out (does not receive
 * a UDP message for more than 30 minutes.)
 * Called during fbCollector_t cleanup.
 */
typedef void            (*fbListenerAppFree_fn) (
    void                        *ctx);

/*
 * Public Function Calls. These calls will remain available and retain
 * their functionality in all subsequent versions of libfixbuf.
 */


/**
 * Set the internal template on a buffer to the given template ID. The internal
 * template describes the format of the record pointed to by the recbase
 * parameter to fBufAppend() (for export) and fBufNext() (for collection). The
 * given template ID must identify a current internal template in the buffer's
 * associated session.
 *
 * An internal template must be set on a buffer before calling fBufAppend() or
 * fBufNext().
 *
 * @param fbuf      an IPFIX message buffer
 * @param int_tid   template ID of the new internal template
 * @param err       An error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fBufSetInternalTemplate(
    fBuf_t              *fbuf,
    uint16_t            int_tid,
    GError              **err);

/**
 * Set the external template for export on a buffer to the given template ID.
 * The external template describes the record that will be written to the
 * IPFIX message. The buffer must be initialized for export. The given ID is
 * scoped to the observation domain of the associated session
 * (see fbSessionSetDomain()), and must identify a current external template
 * for the current domain in the buffer's associated session.
 *
 * An export template must be set on a buffer before calling fBufAppend().
 *
 * @param fbuf      an IPFIX message buffer
 * @param ext_tid   template ID of the new external template within the
 *                  current domain.
 * @param err       An error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fBufSetExportTemplate(
    fBuf_t              *fbuf,
    uint16_t            ext_tid,
    GError              **err);

#if HAVE_SPREAD
/**
 * fBufSetSpreadExportGroup
 *
 * This function checks to see if the groups you are setting on the buffer
 * are different than the groups previously set.  If so, it will emit the
 * buffer, set the first group on the session (to get templates & sequence
 * numbers) and THEN set the desired group(s) for export on a buffer.  This
 * should be called before setting external templates with
 * fbSessionAddTemplate() and before calling fBufAppend().  If using
 * fbSessionAddTemplatesMulticast(), it is not necessary to call this before
 * because it is called within this function.
 *
 * @param fbuf       an IPFIX message buffer
 * @param groups     an array of Spread Export Groups
 * @param num_groups number of groups from groups to be added
 * @param err        an error description, set on failure.
 */
void                 fBufSetSpreadExportGroup(
    fBuf_t             *fbuf,
    char               **groups,
    int                num_groups,
    GError             **err);
#endif

/**
 * Set the automatic mode flag on a buffer. In automatic mode, a call to
 * fBufAppend() or fbSessionExportTemplates() that overruns the available space
 * in the buffer will cause a call to fBufEmit() to emit the message in the
 * buffer to the exporter before starting a new message; and a call to
 * fBufNext() that overruns the buffer will cause a call to fBufNextMessage()
 * to read another message from the collector before attempting to read a
 * record. In manual mode, end of message on any buffer read/write call
 * results in FB_ERROR_EOM. Buffers are created in automatic mode by default.
 *
 * @param fbuf      an IPFIX message buffer
 * @param automatic TRUE for this buffer to be automatic, FALSE for manual.
 */

void                fBufSetAutomaticMode(
    fBuf_t              *fbuf,
    gboolean            automatic);

/**
 * Retrieve the session associated with a buffer.
 *
 * @param fbuf      an IPFIX message buffer
 * @return the associated session
 */

fbSession_t         *fBufGetSession(
    fBuf_t              *fbuf);

/**
 * Free a buffer. Also frees any associated session, exporter, or collector,
 * closing exporting process or collecting process endpoint connections
 * and removing collecting process endpoints from any listeners, as necessary.
 *
 * @param fbuf      an IPFIX message buffer
 */

void                fBufFree(
    fBuf_t              *fbuf);

/**
 * Allocate a new buffer for export. Associates the buffer with a given
 * session and exporting process endpoint; these become owned by the buffer.
 * Session and exporter are freed by fBufFree.  Must never be freed by user
 *
 * @param session   a session initialized with appropriate
 *                  internal and external templates
 * @param exporter  an exporting process endpoint
 * @return a new IPFIX message buffer, owning the session and exporter,
 *         for export use via fBufAppend() and fBufEmit().
 */

fBuf_t              *fBufAllocForExport(
    fbSession_t         *session,
    fbExporter_t        *exporter);

/**
 * Retrieve the exporting process endpoint associated with a buffer.
 * The buffer must have been allocated with fBufAllocForExport();
 * otherwise, returns NULL.
 *
 * @param fbuf      an IPFIX message buffer
 * @return the associated exporting process endpoint
 */

fbExporter_t        *fBufGetExporter(
    fBuf_t              *fbuf);

/**
 * Associate an exporting process endpoint with a buffer.
 * The exporter will be used to write IPFIX messgaes to a transport.
 * The exporter becomes owned by the buffer; any previous exporter
 * associated with the buffer is closed if necessary and freed.
 *
 * @param fbuf      an IPFIX message buffer
 * @param exporter  an exporting process endpoint
 */

void                fBufSetExporter(
    fBuf_t              *fbuf,
    fbExporter_t        *exporter);


/**
 * Append a record to a buffer. Uses the present internal template set via
 * fBufSetInternalTemplate() to describe the record of size recsize located
 * in memory at recbase.  Uses the present export template set via
 * fBufSetExportTemplate() to describe the record structure to be written to
 * the buffer. Information Elements present in the external template that are
 * not present in the internal template are transcoded into the message as
 * zeroes. If the buffer is in automatic mode, may cause a message to be
 * emitted via fBufEmit() if there is insufficient space in the buffer for
 * the record.
 *
 * If the internal template contains any variable length Information Elements,
 * those must be represented in the record by fbVarfield_t structures.
 *
 * @param fbuf      an IPFIX message buffer
 * @param recbase   pointer to internal record
 * @param recsize   size of internal record in bytes
 * @param err       an error description, set on failure.
 *                  Must not be NULL, as it is used internally in
 *                  automatic mode to detect message restart.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fBufAppend(
    fBuf_t              *fbuf,
    uint8_t             *recbase,
    size_t              recsize,
    GError              **err);

/**
 * Emit the message currently in a buffer using the associated exporting
 * process endpoint.
 *
 * @param fbuf      an IPFIX message buffer
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fBufEmit(
    fBuf_t              *fbuf,
    GError              **err);

/**
 * Set the export time on the message currently in a buffer. This will be used
 * as the export time of the message created by the first call to fBufAppend()
 * after the current message, if any, is emitted. Use 0 for the export time
 * to cause the export time to be taken from the system clock at message
 * creation time.
 *
 * @param fbuf      an IPFIX message buffer
 * @param extime    the export time in epoch seconds.
 */

void                fBufSetExportTime(
    fBuf_t              *fbuf,
    uint32_t            extime);

/**
 * Allocate a new buffer for collection. Associates the buffer with a given
 * session and collecting process endpoint; these become owned by the buffer.
 * Session and collector are freed by fBufFree.  Must not be freed by user
 *
 * @param session   a session initialized with appropriate
 *                  internal templates
 * @param collector  an collecting process endpoint
 * @return a new IPFIX message buffer, owning the session and collector,
 *         for collection use via fBufNext() and fBufNextMessage().
 */

fBuf_t              *fBufAllocForCollection(
    fbSession_t         *session,
    fbCollector_t       *collector);

/**
 * Retrieve the collecting process endpoint associated with a buffer.
 * The buffer must have been allocated with fBufAllocForCollection();
 * otherwise, returns NULL.
 *
 * @param fbuf      an IPFIX message buffer
 * @return the associated collecting process endpoint
 */

fbCollector_t       *fBufGetCollector(
    fBuf_t              *fbuf);

/**
 * Associate an collecting process endpoint with a buffer.
 * The collector will be used to read IPFIX messgaes from a transport.
 * The collector becomes owned by the buffer; any previous collector
 * associated with the buffer is closed if necessary and freed.
 *
 * @param fbuf      an IPFIX message buffer
 * @param collector  an collecting process endpoint
 */

void                fBufSetCollector(
    fBuf_t              *fbuf,
    fbCollector_t       *collector);

/**
 * Retrieve a record from a buffer. Uses the external template taken from
 * the message to read the next record available from a data set in the message.
 * Copies the record to a buffer at recbase, with a maximum record size
 * pointed to by recsize, described by the present internal template set via
 * fBufSetInternalTemplate(). Reads and processes any templates and options
 * templates between the last record read (or beginning of message) and the
 * next data record. Information Elements present in the internal template
 * that are not present in the external template are transcoded into the
 * record at recbase as zeroes. If the buffer is in automatic mode, may cause
 * a message to be read via fBufNextMessage() if there are no more records
 * available in the message buffer.
 *
 * If the internal template contains any variable length Information Elements,
 * those must be represented in the record at recbase by fbVarfield_t
 * structures.
 *
 * @param fbuf      an IPFIX message buffer
 * @param recbase   pointer to internal record buffer; will contain
 *                  record data after call.
 * @param recsize   On call, pointer to size of internal record buffer
 *                  in bytes. Contains number of bytes actually transcoded
 *                  at end of call.
 * @param err       an error description, set on failure.
 *                  Must not be NULL, as it is used internally in
 *                  automatic mode to detect message restart.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fBufNext(
    fBuf_t              *fbuf,
    uint8_t             *recbase,
    size_t              *recsize,
    GError              **err);

/**
 * Read a new message into a buffer using the associated collecting
 * process endpoint. Called by fBufNext() on end of message in automatic
 * mode; should be called after an FB_ERROR_EOM return from fBufNext in
 * manual mode, or to skip the current message and go on to the next
 * in the stream.
 *
 * @param fbuf      an IPFIX message buffer
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */


gboolean            fBufNextMessage(
    fBuf_t              *fbuf,
    GError              **err);

/**
 * Retrieve the export time on the message currently in a buffer.
 *
 * @param fbuf      an IPFIX message buffer
 * @return the export time in epoch seconds.
 */

uint32_t            fBufGetExportTime(
    fBuf_t              *fbuf);

/**
 * Retrieve the external template used to read the last record from the buffer.
 * If no record has been read, returns NULL. Stores the external template ID
 * within the current domain in ext_tid, if not NULL.
 *
 * This routine is not particularly useful to applications, as it would be
 * called after the record described by the external template had been
 * transcoded, and as such could not be used to select an
 * appropriate internal template for a given external template. However,
 * it is used by fBufNextCollectionTemplate(), and may be useful in certain
 * contexts, so is made public.
 *
 * Usually, you'll want to use fBufNextCollectionTemplate() instead.
 *
 * @param fbuf      an IPFIX message buffer
 * @param ext_tid   pointer to external template ID storage, or NULL.
 * @return the external template describing the last record read.
 */

fbTemplate_t    *fBufGetCollectionTemplate(
    fBuf_t          *fbuf,
    uint16_t        *ext_tid);

/**
 * Retrieve the external template that will be used to read the next record
 * from the buffer. If no next record is available, returns NULL. Stores the
 * external template ID within the current domain in ext_tid, if not NULL.
 * Reads and processes any templates and options
 * templates between the last record read (or beginning of message) and the
 * next data record. If the buffer is in automatic mode, may cause
 * a message to be read via fBufNextMessage() if there are no more records
 * available in the message buffer.
 *
 * @param fbuf      an IPFIX message buffer
 * @param ext_tid   pointer to external template ID storage, or NULL.
 * @param err       an error description, set on failure.
 *                  Must not be NULL, as it is used internally in
 *                  automatic mode to detect message restart.
 * @return the external template describing the last record read.
 */

fbTemplate_t    *fBufNextCollectionTemplate(
    fBuf_t          *fbuf,
    uint16_t        *ext_tid,
    GError          **err);

/**
 * Allocate a new information model. The information model will contain all
 * the default information elements in the IANA-managed number space, and may
 * be extended via fbInfoModelAddElement() and fbInfoModelAddElementArray().
 *
 * An Information Model is required to create Templates and Sessions. Each
 * application should have only one Information Model.
 *
 * @return a new Information Model
 */

fbInfoModel_t       *fbInfoModelAlloc(void);

/**
 * Free an information model. Must not be called until all sessions and
 * templates depending on the information model have also been freed; i.e.,
 * at application cleanup time.
 *
 * @param model     An information model
 */

void                fbInfoModelFree(
    fbInfoModel_t       *model);

/**
 * Add a single information element to an information
 * model. The information element is assumed to be in "canonical" form; that
 * is, its ref.name field should contain the information element name. The
 * information element and its name are copied into the model; the caller may
 * free or reuse its storage after this call.
 *
 * See fbInfoModelAddElementArray() for a more convenient method of statically
 * adding information elements to information models.
 *
 * @param model     An information model
 * @param ie        Pointer to an information element to copy into the model
 */

void                fbInfoModelAddElement(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ie);

/**
 * Add multiple information elements in an array to an information
 * model. The information elements are assumed to be in "canonical" form; that
 * is, their ref.name fields should contain the information element name. Each
 * information element and its name are copied into the model; the caller may
 * free or reuse its storage after this call.
 *
 * The ie parameter points to the first information element in an array,
 * usually statically initialized with an array of FB_IE_INIT macros followed
 * by an FB_IE_NULL macro.
 * @param model     An information model
 * @param ie        Pointer to an IE array to copy into the model
 */

void                fbInfoModelAddElementArray(
    fbInfoModel_t       *model,
    fbInfoElement_t     *ie);

/**
 * Return a pointer to the canonical information element within an information
 * model given the information element name. The returned information element
 * is owned by the information model and must not be modified.
 *
 * @param model     An information model
 * @param name      The name of the information element to look up
 * @return          The named information element within the model,
 *                  or NULL if no such element exists.
 */

const fbInfoElement_t     *fbInfoModelGetElementByName(
    fbInfoModel_t       *model,
    const char          *name);

/**
 * Return a pointer to the canonical information element within an information
 * model given the information element ID and enterprise ID.  The returned
 * information element is owned by the information model and must not be modified.
 *
 * @param model     An information model
 * @param id        An information element id
 * @param ent       An enterprise id
 * @return          The named information element within the model, or NULL
 *                  if no such element exists.
 */

const fbInfoElement_t    *fbInfoModelGetElementByID(
    fbInfoModel_t       *model,
    uint16_t            id,
    uint32_t            ent);

/**
 * Allocate a new empty template. The template will be associated with the
 * given Information Model, and only able to use Information Elements defined
 * within that Information Model. Templates may be associated with multiple
 * sessions, with different template IDs each time, and as such are
 * reference counted and owned by sessions. A template must be associated
 * with at least one session or it will be leaked; each template is freed
 * after its last associated session is freed.
 *
 * Use fbTemplateAppend(), fbTemplateAppendSpec(), and
 * fbTemplateAppendSpecArray() to "fill in" a template after creating it,
 * and before associating it with any session.
 *
 * @param model     An information model
 * @return a new, empty Template.
 */

fbTemplate_t        *fbTemplateAlloc(
    fbInfoModel_t       *model);

/**
 * Append an information element to a template. The information element is taken
 * to be an example; the canonical element from the template's associated model
 * is looked up by enterprise and element number and copied. If no information
 * element exists in the model with the given enterprise and element number,
 * it is copied to the model with the name "_alienInformationElement".
 *
 * This call is intended primarily for use by fBuf_t's template reader, but can
 * also be useful to simulate receipt of templates over the wire.
 *
 * @param tmpl      Template to append information element to
 * @param ex_ie     Example IE to add to the template
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbTemplateAppend(
    fbTemplate_t        *tmpl,
    fbInfoElement_t     *ex_ie,
    GError              **err);

/**
 * Append an information element described by specifier to a template.
 * The information element named by the specifier is copied from the template's
 * associated model, and the length and flags are overriden from the specifier.
 *
 * @param tmpl      Template to append information element to.
 * @param spec      Specifier describing information element to append.
 * @param flags     Application flags. Must match one bit of spec flags word
 *                  or the append will be silently skipped. Used for
 *                  building multiple templates with different information
 *                  element features from a single specifier.
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbTemplateAppendSpec(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec,
    uint32_t            flags,
    GError              **err);

/**
 * Append information elements described by a specifier array to a template.
 * The information elements named by the specifiers are copied from the
 * template's associated model, and the length and flags are overriden from
 * each specifier. The array is read until the FB_IESPEC_NULL convenience macro
 * is encountered.
 *
 * @param tmpl      Template to append information element to.
 * @param spec      Pointer to first specifier in specifier array to append.
 * @param flags     Application flags. Must contain all bits of spec flags word
 *                  or the append will be silently skipped. Used for
 *                  building multiple templates with different information
 *                  element features from a single specifier.
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbTemplateAppendSpecArray(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec,
    uint32_t            flags,
    GError              **err);

/**
 * Determine number of information elements in a template.
 *
 * @param tmpl      A template
 * @return information element count
 */

uint32_t            fbTemplateCountElements(
    fbTemplate_t        *tmpl);

/**
 * Set the number of information elements in a template that are scope. This
 * causes the template to become an options template, and must be called after
 * all the scope information elements have been appended to the template.
 *
 * @param tmpl          Template to set scope on
 * @param scope_count   Number of scope information elements
 */

void                fbTemplateSetOptionsScope(
    fbTemplate_t        *tmpl,
    uint16_t            scope_count);

/**
 * Determine number of scope information elements in a template. The template
 * is an options template if nonzero.
 *
 * @param tmpl      A template
 * @return scope information element count
 */
uint32_t            fbTemplateGetOptionsScope(
    fbTemplate_t        *tmpl);

/**
 * Determine if a template contains a given information element. Matches against
 * information element private enterprise number, number, and multiple-IE index
 * (i.e., to determine if a given template contains six instances of a given
 * information element, set ex_ie->midx = 5 before this call).
 *
 * @param tmpl      Template to search
 * @param ex_ie     Pointer to an information element to search for
 * @return          TRUE if the template contains the given IE
 */

gboolean           fbTemplateContainsElement(
    fbTemplate_t            *tmpl,
    const fbInfoElement_t   *ex_ie);

/**
 * Determine if a template contains at least one instance of a given
 * information element, specified by name in the template's information model.
 *
 * @param tmpl      Template to search
 * @param spec      Specifier of information element to search for
 * @return          TRUE if the template contains the given IE
 */

gboolean           fbTemplateContainsElementByName(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec);

/**
 * Determine if a template contains at least one instance of each
 * information element in a given information element specifier array.
 *
 * @param tmpl      Template to search
 * @param spec      Pointer to specifier array to search for
 * @return          TRUE if the template contains all the given IEs
 */

gboolean           fbTemplateContainsAllElementsByName(
    fbTemplate_t        *tmpl,
    fbInfoElementSpec_t *spec);

/**
 * Free a template if it is not currently in use by any Session. Use this
 * to clean up while creating templates in case of error.
 *
 * @param tmpl template to free
 */

void                fbTemplateFreeUnused(
    fbTemplate_t        *tmpl);

/**
 * Allocate a transport session state container. The new session is associated
 * with the given information model, contains no templates, and is usable
 * either for collection or export.
 *
 * Each fbExporter_t, fbListener_t, and fbCollector_t must have its own session;
 * session state cannot be shared.
 *
 * @param model     An information model.  Not freed by sessionFree.  Must
                    be freed by user after calling SessionFree
 * @return a new, empty session state container.
 */

fbSession_t         *fbSessionAlloc(
    fbInfoModel_t       *model);

/**
 * This function sets the callback to let the user know when a new template
 * has arrived from the connected IPFIX node.  Assigning a callback here
 * is NOT required.  Not using one will cause all sub templates to be fully
 * decoded, transcoding all information elements in the external template.
 * This function needs to be called AFTER a new connection has been made,
 * usually after the call to fbListenerWait, which creates a new fBuf and
 * session for that connection.
 *
 * @param session pointer to the session to assign the callback to
 * @param callback the function to be called when a new template is received
 * @return NONE
 */
void fbSessionAddTemplateCallback(
    fbSession_t                *session,
    fbNewTemplateCallback_fn    callback);

/**
 * Adds an external-internal template pair to the session.  This tells the
 * transcoder which internal template to use for a given external template
 * used in a sub template list, or a sub template multi list
 *
 * If ent_tid and int_tid are set equal to each other, it tells the transcoder
 * to decode all of the fields from the external template, by using the
 * external template also as the internal template (lining up all the fields)
 * The exception to this is if there is an existing internal template with
 * the same template ID as the external template. In this case, the internal
 * template with the appropriate ID will be used. To avoid this potentially
 * unintended consequence, be careful and deliberate with template IDs.
 *
 * @param session pointer to the session to add the pair to
 * @param ent_tid the external template ID
 * @param int_tid the internal template ID used to decode the data when the
                  associated external template is used
 * @return NONE
 */
void fbSessionAddTemplatePair(
    fbSession_t    *session,
    uint16_t        ent_tid,
    uint16_t        int_tid);

/**
 * remove a template pair from the list
 * this is called by fixbuf when a template is revoked from the session by
 * the node on the other end of the connection
 *
 * @param session pointer to the session to remove the pair from
 * @param ext_tid the external template ID for the pair
 * @return NONE
 */
void fbSessionRemoveTemplatePair(
    fbSession_t    *session,
    uint16_t        ext_tid);

/**
 * Function to find a pair, uniquely identified by the external ID, and return
 * the associated internal template ID
 *
 * @param session pointer to the session used to find the pair
 * @param ext_tid external template ID used to find a pair
 * @return the internal template ID from the pair.  0 if the pair isn't found
 */
uint16_t    fbSessionLookupTemplatePair(
    fbSession_t    *session,
    uint16_t        ext_tid);

/**
 * Free a transport session state container. This is done automatically when
 * freeing the listener or buffer with which the session is
 * associated. Use this call if a session needs to be destroyed before it
 * is associated.
 *
 * @param session   session state container to free.
 */

void                fbSessionFree(
    fbSession_t         *session);

/**
 * Reset the external state (sequence numbers and templates) in a session
 * state container.
 *
 * FIXME: Verify that this call actually makes sense; either that a session
 * is reassociatable with a new collector, or that you need to do this when
 * reassociating a collector with a connection. Once this is done, rewrite
 * this documentation
 *
 * @param session   session state container to reset
 */

void                fbSessionResetExternal(
    fbSession_t         *session);

/**
 * Set the current observation domain on a session. The domain
 * is used to scope sequence numbers and external templates. This is called
 * automatically during collection, but must be called to set the domain
 * for export before adding external templates or writing records.
 *
 * Notice that a domain change does not automatically cause any associated
 * export buffers to emit messages; a domain change takes effect with the
 * next message started. Therefore, call fBufEmit() before setting the domain
 * on the buffer's associated session.
 *
 * @param session   a session state container
 * @param domain    ID of the observation domain to set
 */

void                fbSessionSetDomain(
    fbSession_t         *session,
    uint32_t            domain);

/**
 * Retrieve the current domain on a session.
 *
 * @param session a session state container
 * @return the ID of the session's current observation domain
 */

uint32_t            fbSessionGetDomain(
    fbSession_t         *session);

#if HAVE_SPREAD
/**
 * fbSessionAddTemplatesMulticast
 *
 * Set and send templates for 1 or more groups.
 * This loops through the groups and adds the template to each
 * group's session and adds the template to the buffer.
 * This function is really meant for external templates, since
 * they are exported, although can be used for internal templates.
 * Since internal templates are not managed per group, they can simply
 * be added with fbSessionAddTemplate().
 * It is necessary to use this function if you plan on managing
 * templates per group.  Using fbSessionAddTemplate() will not allow
 * you to send a tmpl(s) to more than 1 group.
 *
 * @param session    a session state container
 * @param group      group names
 * @param internal   TRUE for internal tmpl, FALSE for external
 * @param tid        template id
 * @param tmpl       pointer to template with template id tid
 * @param err        error mesasge
 */
gboolean        fbSessionAddTemplatesMulticast(
    fbSession_t      *session,
    char             **groups,
    gboolean         internal,
    uint16_t         tid,
    fbTemplate_t     *tmpl,
    GError           **err);

#endif

/**
 * Export a single external template in the current domain of a given session.
 * Writes the template to the associated export buffer. May cause a message to
 * be emitted if the associated export buffer is in automatic mode, or return
 * with FB_ERROR_EOM if the associated export buffer is not in automatic mode.
 *
 * @param session   a session state container associated with an export buffer
 * @param tid       template ID within current domain to export
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbSessionExportTemplate(
    fbSession_t         *session,
    uint16_t            tid,
    GError              **err);

/**
 * Export all external templates in the current domain of a given session.
 * Writes templates to the associated export buffer. May cause a message to
 * be emitted if the associated export buffer is in automatic mode, or return
 * with FB_ERROR_EOM if the associated export buffer is not in automatic mode.
 *
 * @param session   a session state container associated with an export buffer
 * @param err       an error description, set on failure.
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbSessionExportTemplates(
    fbSession_t         *session,
    GError              **err);

/**
 * Add a template to a session. If external, adds the template to the current
 * domain, and exports the template if the session is associated with an export
 * buffer. Assigns the template ID given in tid, or assigns a template ID if
 * tid is FB_TID_AUTO.
 * If using FB_TID_AUTO, external templates start at 256 and count up, internal
 * templates start at 65535 and count down. This is to avoid inadvertant
 * unrelated external and internal templates having the same ID
 *
 * @param session   A session state container
 * @param internal  TRUE if the template is internal, FALSE if external.
 * @param tid       Template ID to assign, replacing any current template
 *                  in case of collision; or FB_TID_AUTO to assign a new tId.
 * @param tmpl      Template to add
 * @param err       An error description, set on failure
 * @return the template ID of the added template, or 0 on failure.
 */

uint16_t            fbSessionAddTemplate(
    fbSession_t         *session,
    gboolean            internal,
    uint16_t            tid,
    fbTemplate_t        *tmpl,
    GError              **err);

/**
 * Remove a template from a session.  If external, removes the template from
 * the current domain, and exports a template revocation set if the session is
 * associated with an export buffer.
 *
 * @param session   A session state container
 * @param internal  TRUE if the template is internal, FALSE if external.
 * @param tid       Template ID to remove.
 * @param err       An error description, set on failure
 * @return TRUE on success, FALSE on failure.
 */

gboolean            fbSessionRemoveTemplate(
    fbSession_t         *session,
    gboolean            internal,
    uint16_t            tid,
    GError              **err);

/**
 * Retrieve a template from a session by ID. If external, retrieves the
 * template within the current domain.
 *
 * @param session   A session state container
 * @param internal  TRUE if the template is internal, FALSE if external.
 * @param tid       ID of the template to retrieve.
 * @param err       An error description, set on failure.
 * @return The template with the given ID, or NULL on failure.
 */

fbTemplate_t        *fbSessionGetTemplate(
    fbSession_t         *session,
    gboolean            internal,
    uint16_t            tid,
    GError              **err);

/**
 * Allocate an exporting process endpoint for a network connection.
 * The remote collecting process is specified by the given connection specifier.
 * The underlying socket connection will not be opened until the first message
 * is emitted from the buffer associated with the exporter.
 *
 * @param spec      remote endpoint connection specifier.  A copy is made
                    for the exporter, it is freed later.  User is responsible
                    for original spec pointer
 * @return a new exporting process endpoint
 */

fbExporter_t        *fbExporterAllocNet(
    fbConnSpec_t        *spec);

#if HAVE_SPREAD
/**
 * fbCollectorGetSpreadReturnGroups
 *
 * This function is useful if need to know what groups were set on the message.
 * Also useful if you are subscribed to more than 1 group, or want to know
 * what other groups the message published to.
 *
 * @param collector
 * @param array of groups
 * @return number in the array of groups
 */
int fbCollectorGetSpreadReturnGroups(
    fbCollector_t *collector,
    char *groups[]);

/**
 *  Allocate an exporting process endpoint for a Spread connection.
 *  This connection will use the Spread toolkit for exporting and collecting
 *  IPFIX records.  Note that the connection to the Spread daemon will not
 *  take place until the first message is emitted from the buffer.
 *  This is not synonymous with appending the first record to the buffer.
 *  NOTE: unlike the other connection specifiers, the session MUST be set
 *  in the fbSpreadSpec_t structure BEFORE it is passed to this method.
 *
 * @param params      Spread connection specifier
 * @return a new exporting process endpoint
 */

fbExporter_t        *fbExporterAllocSpread(
    fbSpreadParams_t      *params );

#endif /* HAVE_SPREAD */

/**
 * Allocate an exporting process endpoint for a named file. The underlying
 * file will not be opened until the first message is emitted from the
 * buffer associated with the exporter.
 *
 * @param path      pathname of the IPFIX File to write, or "-" to
 *                  open standard output.  Path is duplicated and handled.
                    Original pointer is up to the user.
 * @return a new exporting process endpoint
 */

fbExporter_t        *fbExporterAllocFile(
    const char          *path);

/**
 * Allocate an exporting process endpoint for an opened ANSI C file pointer.
 *
 * @param fp        open file pointer to write to.  File pointer is created
                    and freed outside of the Exporter functions.
 * @return a new exporting process endpoint
 */

fbExporter_t        *fbExporterAllocFP(
    FILE                *fp);

/**
 * Set the SCTP stream for the next message exported. To change the SCTP
 * stream used for export, first emit any message in the exporter's associated
 * buffer with fbufEmit(), then use this call to set the stream for the next
 * message. This call cancels automatic stream selection, use
 * fbExporterAutoStream() to re-enable it. This call is a no-op for non-SCTP
 * exporters.
 *
 * @param exporter      an exporting process endpoint.
 * @param sctp_stream   SCTP stream to use for next message.
 */

void                fbExporterSetStream(
    fbExporter_t        *exporter,
    int                 sctp_stream);

/**
 * Enable automatic SCTP stream selection for the next message exported.
 * Automatic stream selection is the default; use this call to re-enable it
 * on a given exporter after using fbExporterSetStream(). With automatic
 * stream selection, the minimal behavior specified in the original IPFIX
 * protocol (RFC xxxx) is used: all templates and options templates are
 * exported on stream 0, and all data is exported on stream 1. This call is a
 * no-op for non-SCTP exporters.
 *
 * @param exporter      an exporting process endpoint.
 */

void                fbExporterAutoStream(
    fbExporter_t        *exporter);

/**
 * Force the file or socket underlying an exporting process endpoint to close.
 * No effect on open file endpoints. The file or socket may be reopened on a
 * subsequent message emission from the associated buffer.
 *
 * @param exporter  an exporting process endpoint.
 */
void                fbExporterClose(
    fbExporter_t       *exporter);

/**
 * Allocate a collecting process endpoint for a named file. The underlying
 * file will be opened immediately.
 *
 * @param ctx       application context; for application use, retrievable
 *                  by fbCollectorGetContext
 * @param path      path of file to read, or "-" to read standard input.
                    Used to get fp, user creates and frees.
 * @param err       An error description, set on failure.
 * @return a collecting process endpoint, or NULL on failure.
 */

fbCollector_t       *fbCollectorAllocFile(
    void                *ctx,
    const char          *path,
    GError              **err);

/**
 * Allocate a collecting process endpoint for an open file.
 *
 * @param ctx       application context; for application use, retrievable
 *                  by fbCollectorGetContext
 * @param fp      file pointer to file to read.  Created and freed by user.
                    Must be kept around for the life of the collector.
 * @return a collecting process endpoint.
 */

fbCollector_t       *fbCollectorAllocFP(
    void                *ctx,
    FILE                *fp);


#ifdef HAVE_SPREAD
/**
*   Allocate a collecting process endpoint for the Spread transport.
*
*   @param ctx      application context
*   @param params   point to fbSpreadSpec_t containing Spread params
*   @param err      error description, set on failure
*
*   @return         a collecting endpoint, or null on failure
*/

fbCollector_t       *fbCollectorAllocSpread (
    void                *ctx,
    fbSpreadParams_t    *params,
    GError              **err );

#endif /* HAVE_SPREAD */

/**
 * Retrieve the application context associated with a collector. This context
 * is taken from the ctx argument of fbCollectorAllocFile() or
 * fbCollectorAllocFP(), or passed out via the ctx argument to the
 * appinit function argument to fbListenerAlloc().
 *
 * @param collector a collecting process endpoint.
 * @return the application context
 */

void                *fbCollectorGetContext(
    fbCollector_t       *collector);

/**
 * Close the file or socket underlying a collecting process endpoint.
 * No effect on open file endpoints. If the collector is attached to a
 * buffer managed by a listener, the buffer will be removed from the
 * listener (that is, it will not be returned by subsequent fbListenerWait()
 * calls).
 *
 * @param collector  a collecting process endpoint.
 */

void                fbCollectorClose(
    fbCollector_t       *collector);


/**
 * Set the collector to only receive from the given IP address over UDP.
 * The port will be ignored.  Use fbListenerGetCollector() to get the pointer
 * to the collector after calling fbListenerAlloc(). ONLY valid for UDP.
 * Set the address family in address.
 *
 * @param collector pointer to collector
 * @param address pointer to sockaddr struct with IP address and family.
 * @param address_length address length
 *
 */
void                fbCollectorSetAcceptOnly(
    fbCollector_t       *collector,
    struct sockaddr     *address,
    size_t              address_length);

/**
 * Allocate a listener. The listener will listen on a specified local endpoint,
 * and create a new collecting process endpoint and collection buffer for each
 * incoming connection. Each new buffer will be associated with a clone of
 * a given session state container.
 *
 * The application may associate context with each created collecting process
 * endpoint, or veto a connection attempt, via a function colled on each
 * connection attempt passed in via the appinit parameter. If this function
 * will create application context, provide a function via the appfree parameter
 * which will free it.
 *
 * @param spec      local endpoint connection specifier.
                    A copy is made of this, which is freed by listener.
                    Original pointer freeing is up to the user.
 * @param session   session state container to clone for each collection buffer
 *                  created by the listener.  Not freed by listener.  Must
 *                  be kept alive while listener exists.
 * @param appinit   application connection initiation function. Called on each
 *                  collection attempt; vetoes connection attempts and creates
 *                  application context.
 * @param appfree   application context free function.
 * @param err       An error description, set on failure.
 * @return a new listener, or NULL on failure.
 */
fbListener_t        *fbListenerAlloc(
    fbConnSpec_t            *spec,
    fbSession_t             *session,
    fbListenerAppInit_fn    appinit,
    fbListenerAppFree_fn    appfree,
    GError                  **err);

/**
 * Free a listener. Stops listening on the local endpoint, and frees any
 * open buffers still managed by the listener.
 *
 * @param listener a listener
 */

void                fbListenerFree(
    fbListener_t            *listener);

/**
 * Wait on a listener. Accepts pending connections from exporting processes.
 * Returns the next collection buffer with available data to read; if the
 * collection buffer returned by the last call to fbListenerWait() is available,
 * it is preferred. Blocks forever (or until fbListenerInterrupt() is called)
 * if no messages or connections are available.
 *
 * To effectively use fbListenerWait(), the application should set up an
 * session state container with internal templates, call fbListenerWait()
 * to accept a first connection, then read records from the collector buffer
 * to end of message (FB_ERROR_EOM). At end of message, the application should
 * then call fbListenerWait() to accept pending connections or switch to
 * another collector buffer with available data. Note that each collector
 * buffer returned created by fbListenerWait() is set to manual mode using
 * fBufSetAutomaticMode().
 *
 * @param listener  a listener
 * @param err       An error description, set on failure.
 * @return a collection buffer with available data, or NULL on failure.
 */

fBuf_t              *fbListenerWait(
    fbListener_t            *listener,
    GError                  **err);

/**
 * Waits for an incoming connection, just like fbListenerWait, except that
 * this function doesn't monitor active collectors.  This allows for a
 * multi threaded application to have one thread monitoring the listeners,
 * and one keeping track of collectors
 * @param listener  The listener to wait for connections on
 * @param err       An error description, set on failure.
 * @return a collection buffer for the new connection, NULL on failure.
 */

fBuf_t              *fbListenerWaitNoCollectors(
    fbListener_t            *listener,
    GError                  **err);

/**
 * Cause the current or next call to fbListenerWait to unblock and return.
 * Use this from a thread or a signal handler to interrupt a blocked listener.
 *
 * @param listener listener to interrupt.
 */

void                fbListenerInterrupt(
    fbListener_t            *listener);


/**
 *fbListenerGetCollector
 *
 * If a collector is associated with the listener class, this will return a
 * handle to the collector state structure.
 *
 * @param listener handle to the listener state
 * @param collector pointer to a collector state pointer, set on return
 *        if there is no error
 *
 * @param err a GError structure holding an error message on error
 *
 * @return FALSE on error, check err, TRUE on success
 *
 */
gboolean            fbListenerGetCollector(
    fbListener_t        *listener,
    fbCollector_t       **collector,
    GError              **err);




/**
 * fbCollectorClearTranslator
 *
 * this removes an input translator from a given
 * collector such that it will operate on IPFIX
 * protocol again
 *
 * @param collector the collector on which to remove
 *        the translator
 *
 * @param err when an error occurs, a Glib GError
 *        structure is set with an error description
 *
 * @return TRUE on success, FALSE on failure
 */
gboolean    fbCollectorClearTranslator(
    fbCollector_t   *collector,
    GError          **err);


/**
 *fbCollectorSetNetflowV9Translator
 *
 * this sets the collector input translator
 * to convert NetFlowV9 into IPFIX for the
 * given collector
 *
 * @param collector pointer to the collector state
 *        to perform Netflow V9 conversion on
 * @param err GError structure that holds the error
 *        message if an error occurs
 *
 *
 * @return TRUE on success, FALSE on error
 */
gboolean    fbCollectorSetNetflowV9Translator(
    fbCollector_t               *collector,
    GError                      **err);

/**
 * fbCollectorGetNetflowMissed
 *
 * Returns the number of potential missed export packets of the Netflow
 * v9 session that is currently set on the collector (the session is set on
 * the collector when an export packet is received) if peer is NULL.  If peer
 * is set, this will look up the session for that peer/obdomain pair and return
 * the missed export packets associated with that peer and obdomain.  If
 * peer/obdomain pair doesn't exist, this function returns 0.
 * This can't return the number of missed flow records since Netflow v9
 * increases sequence numbers by the number of export packets it has sent,
 * NOT the number of flow records (like IPFIX and netflow v5 does).
 *
 * @param collector
 * @param peer [OPTIONAL] peer address of NetFlow v9 exporter
 * @param peerlen size of peer object
 * @param obdomain observation domain of NetFlow v9 exporter
 * @return number of missed packets since beginning of session
 *
 */
uint32_t fbCollectorGetNetflowMissed(
    fbCollector_t         *collector,
    struct sockaddr       *peer,
    size_t                 peerlen,
    uint32_t               obdomain);

/**
 * Retrieves information about the node connected to this collector
 *
 * @param collector pointer to the collector to get peer information from
 * @return pointer to sockaddr structure containing IP information of peer
 */
struct sockaddr* fbCollectorGetPeer(
    fbCollector_t   *collector);

/**
 * Retrieves the observation domain of the node connected to the collector
 *
 * @param collector
 *
 */
uint32_t fbCollectorGetObservationDomain(
    fbCollector_t  *collector);

/**
 * Attempt to maintain backwards compatibility with UDP.  As of version 1.2,
 * fixbuf calls the appinit functions when a new UDP connection occurs, as
 * opposed to calling it during fbListenerAlloc.  To maintain compatibility,
 * with old applications, fixbuf will still call appinit in fbListenerAlloc
 * with a null peer address.  If UDP multi session is turned on, it will ALSO
 * call appinit() when a new UDP connection occurs.  Likewise with appfree().
 * Call fbListenerGetCollector() to obtain collector.
 *
 * @param collector     pointer to collector associated with listener.
 * @param multi_session TRUE if multi-session enabled, FALSE by default.
 */
void fbCollectorSetUDPMultiSession(
    fbCollector_t *collector,
    gboolean       multi_session);

/**
 * An attempt to fix what some netflow v9 exporters do wrong.
 * Netflow v9 rfc 3954 states that collectors should use a combination of
 * peer IP address and observation domain to manage netflow streams.
 * However, some devices send two separate streams on the same IP, obdomain,
 * and the only way to differentiate is by using peer port. Turning this
 * flag on will prevent fixbuf from zeroing out the port before comparing
 * sockaddr structs and makes fixbuf manage streams by ip, port, and obdomain.
 *
 * @param collector     pointer to collector associated with listener.
 * @param manage_port   TRUE if fixbuf should manage UDP streams by port,
 *                      FALSE by default.
 *
 */
void fbCollectorManageUDPStreamByPort(
    fbCollector_t *collector,
    gboolean       manage_port);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
