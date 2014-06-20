/** @internal
 **
 **
 ** @file fbcollector.h
 ** IPFIX Collecting Process single transport session implementation
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



#ifndef FB_COLLECTOR_H_
#define FB_COLLECTOR_H_

#define _FIXBUF_SOURCE_
#include <fixbuf/public.h>

#ident "$Id: fbcollector.h 18731 2013-02-28 15:59:53Z ecoff_svn $"

/* 30 mins in seconds */
#define FB_UDP_TIMEOUT 1800

/**
 * fbCollectorClose_fn
 *
 * the close function for a given collector; it is transport
 * specific
 *
 * @param collector the handle to the collecting process
 *
 */
typedef void        (*fbCollectorClose_fn)(
    fbCollector_t               *collector);



/** structure definition of the start of IPFIX & NetFlow messages */
typedef struct fbCollectorMsgVL_st {
    uint16_t                    n_version;
    uint16_t                    n_len;
} fbCollectorMsgVL_t;


/**
 * fbCollectorClearTranslator
 *
 * After setting an input translator for a collector, this function clears
 * that operation.  The collector, after this call, will again operate as
 * an IPFIX collector.
 *
 * @param collector a collecting process endpoint.
 * @param err An error message set on return when an error occurs
 *
 * @return TRUE on success, FALSE on error
 */
gboolean    fbCollectorClearTranslator(
    fbCollector_t   *collector,
    GError          **err);


/**
 * fbCollectorPostProc_fn
 *
 * The defines the function for the post processing function for
 * implementing a translator to IPFIX.  This gets called after
 * a PDU for the protocol is read.
 *
 * @param collector a collecting process endpoint
 * @param dataBuf a pointer to the PDU body
 * @param err An error message set on return when an error occurs
 *
 * @return TRUE of success, FALSE on error
 */
typedef gboolean    (*fbCollectorPostProc_fn)(
    fbCollector_t               *collector,
    uint8_t                     *dataBuf,
    size_t                      *bufLen,
    GError                      **err);


/**
 * fbCollectorVLMessageSize_fn
 *
 * This function returns the size of the PDU for a read.  It is
 * specific to the protocol to be translated.
 *
 * @param collector a collecting process endpoint
 * @param hdr a pointer to the IPFIX header (although can be cast
 *            into a uint8_t * and used as a pointer into the
 *            buffer)
 * @param b_len the length of the header just read in
 * @param m_len a return value with the length of the PDU to be read
 * @param err An error message set on the return when an error occurs
 *
 * @return TRUE on success, FALSE on error
 */
typedef gboolean    (*fbCollectorVLMessageSize_fn)(
    fbCollector_t               *collector,
    fbCollectorMsgVL_t          *hdr,
    size_t                      b_len,
    uint16_t                    *m_len,
    GError                      **err);

/**
 * fbCollectorMessageHeader_fn
 *
 * This function is called for message based read channels when the
 * fbCollectorVLMessageSize_fn is not called.  (UDP & SCTP)  TCP &
 * files are read as streams and the concept of a PDU doesn't exist
 * in the same fashion as message based protocols.  This function
 * reconstructs the header of a message in order for it to be workable
 * with the fbCollectorPostProc_fn.
 *
 * Or you could view it this way, this function is the result of taking
 * an optimization in fbCollectorVLMessageSize_fn which modifies the
 * header in order to avoid a mempy.  This is where the memcpy happens
 * if you don't call fbCollectorVLMessageSize_fn.  (At least for NetFlow
 * V9.)
 *
 * @param collector pointer to the collector state structure
 * @param buffer pointer to the raw data buffer
 * @param b_len length of the buffer passed in
 * @param m_len length of the message on output (might be different
 *              than b_len from transformations made here)
 * @param err An error message set on return if an error occurs
 *
 * @return TRUE on success, FALSE on error (check err)
 *
 */
typedef gboolean    (*fbCollectorMessageHeader_fn)(
    fbCollector_t               *collector,
    uint8_t                     *buffer,
    size_t                      b_len,
    uint16_t                    *m_len,
    GError                      **err);

/**
 * fbCollectorTransClose_fn
 *
 * This is called to cleanup any translator state when a collector
 * with a translator is closed.
 *
 * @param collector a collecting process endpoint
 *
 */
typedef void        (*fbCollectorTransClose_fn)(
    fbCollector_t               *collector);


/**
 * fbCollectorSessionTimeout_fn
 *
 * This is the definition of the function the collector calls when it
 * times out a UDP session.  It needs to be a function pointer to allow
 * translators the ability to free any state that is associated with
 * the timed out session.
 *
 * @param collector pointer to collector
 * @param session pointer to session that is being timed out
 *
*/
typedef void (*fbCollectorSessionTimeout_fn) (
    fbCollector_t                *collector,
    fbSession_t                  *session);


/**
 * fbCollectorSetTranslator
 *
 * This sets a translator on the given collecting process.  There are various
 * function points that need to be set in order to implement a collector that
 * can read something other than IPFIX, e.g. NetFlow.  Not all functions need
 * to be reimplemented, depending on the protocol to be adapted, however, a
 * valid function pointer needs to be provided for each function.  The
 * fbcollector and fbnetflow source code can provide more detailed example
 * and information about the exact implementation.
 *
 * @param collector a collecting process endpoint
 * @param postProcFunc a function that gets called after a pdu has been read
 *                     so that any necessary transformations may occur
 * @param vlMessageFunc this function is used to determine how large a single
 *                      read should be from the file/network handle; it should
 *                      return a whole PDU if possible
 * @param headerFunc function to transform the header after a block read before
 *                      it is sent to the postProcFunc (called when
 *                      vlMessageFunc isn't)
 * @param trCloseFunc this function gets called when the collector gets closed
 *                    to clean up any data, etc. that the the translator
 *                    requires
 * @param timeOutFunc this function gets called when the collector times out
 *                    UDP sessions, so it can clear any related state.
 * @param opaque the fixbuf standard collector code will not look at this
 *               pointer.  The translator can use this and retrieve it from
 *               the collector structure as needed during its operation
 * @param err An error message set on return when an error occurs
 *
 * @return TRUE on success, FALSE on error
 */
gboolean    fbCollectorSetTranslator(
    fbCollector_t                *collector,
    fbCollectorPostProc_fn       postProcFunc,
    fbCollectorVLMessageSize_fn  vlMessageFunc,
    fbCollectorMessageHeader_fn  headerFunc,
    fbCollectorTransClose_fn     trCloseFunc,
    fbCollectorSessionTimeout_fn timeOutFunc,
    void                         *opaque,
    GError                       **err);


/**
 * fbCollectorRead_fn
 *
 * This is the definition of the read function the collector calls in order
 * to read a PDU from the stream/file.  It is defined as a function pointer
 * to be able to accomodate the various different connection types supported
 * by fixbuf.
 *
 * @param collector a collecting process endpoint
 * @param msgbase the buffer to store the PDU in
 * @param msglen the length of the PDU stored in msgbase
 * @param err An error message set on return of a failure
 *
 * @return TRUE on success, FALSE on error
 *
 */
typedef gboolean    (*fbCollectorRead_fn) (
    fbCollector_t               *collector,
    uint8_t                     *msgbase,
    size_t                      *msglen,
    GError                      **err);


struct fbCollector_st {
    /** Listener from which this Collector was created. */
    fbListener_t                *listener;
    /**
     * Application context. Created and owned by the application
     * when the listener calls the <new collector> callback.
     */
    void                        *ctx;
    /** Cached peer address. Filled in at allocation time */
    union {
        struct sockaddr         so;
        struct sockaddr_in      ip4;
        struct sockaddr_in6     ip6;
    }                           peer;
    /** Current export stream */
    union {
        /** Buffered file pointer, for file transport */
        FILE                    *fp;
        /**
         * Unbuffered socket, for SCTP, TCP, or UDP transport.
         * Also used as base socket for TLS and DTLS support.
         */
        int                     fd;
        #ifdef HAVE_SPREAD
        fbSpreadSpec_t *        spread;
        #endif
    }                           stream;

    /**
     * Interrupt pipe read end file descriptor.
     * Used to unblock a call to fbListenerWait().
     */
    int                         rip;
    /**
     * Interrupt pipe write end file descriptor.
     * Used to unblock a call to fbListenerWait().
     */
    int                         wip;
    gboolean                    bufferedStream;
    gboolean                    translationActive;
    gboolean                    active;
    gboolean                    accept_only;
    gboolean                    multi_session;
    gboolean                    stream_by_port;
    uint32_t                    obdomain;
    time_t                      time;
#if HAVE_OPENSSL
    /** OpenSSL socket, for TLS or DTLS over the socket in fd. */
    SSL                         *ssl;
#endif
#if HAVE_SPREAD
    /** Need something to distinguish collectors if we have spread but don't
        use it */
    uint8_t                    spread_active;
#endif
    fbCollectorRead_fn          coread;
    fbCollectorVLMessageSize_fn coreadLen;
    fbCollectorPostProc_fn      copostRead;
    fbCollectorMessageHeader_fn comsgHeader;
    fbCollectorClose_fn         coclose;
    fbCollectorTransClose_fn    cotransClose;
    fbCollectorSessionTimeout_fn cotimeOut;
    void                        *translatorState;
    fbUDPConnSpec_t             *udp_head;
    fbUDPConnSpec_t             *udp_tail;
};

#endif
