/** @internal
 **
 **
 ** @file fbcollector.c
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

/*#define _GNU_SOURCE*/
#define _FIXBUF_SOURCE_
#include <fixbuf/private.h>

#include "fbcollector.h"

#ident "$Id: fbcollector.c 18731 2013-02-28 15:59:53Z ecoff_svn $"

/*#################################################
 *
 * IPFIX functions for reading input, these are
 * the default functions
 *
 *#################################################*/


/**
 * fbCollectorDecodeMsgVL
 *
 * decodes the header of a variable length message to determine
 * how long the message is in order to read the appropriate
 * amount to complete the message
 *
 *
 * @return FALSE on error, TRUE on success
 */
static gboolean fbCollectorDecodeMsgVL(
    fbCollector_t               *collector,
    fbCollectorMsgVL_t          *hdr,
    size_t                      b_len,
    uint16_t                    *m_len,
    GError                      **err)
{
    uint16_t                    h_version;
    uint16_t                    h_len;

    /* collector is unused in this function*/
    (void)collector;

    h_version = g_ntohs(hdr->n_version);
    if (h_version != 0x000A) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Illegal IPFIX Message version 0x%04x; "
                    "input is probably not an IPFIX Message stream.",
                    g_ntohs(hdr->n_version));
        *m_len = 0;
        return FALSE;
    }

    h_len = g_ntohs(hdr->n_len);
    if (h_len < 16) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IPFIX,
                    "Illegal IPFIX Message length 0x%04x; "
                    "input is probably not an IPFIX Message stream.",
                    g_ntohs(hdr->n_len));
        *m_len = 0;
        return FALSE;
    }

    if (b_len && (h_len > b_len)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_BUFSZ,
                    "Buffer too small to read IPFIX Message "
                    "(message size %hu, buffer size %u).",
                    h_len, (uint32_t)b_len);
        *m_len = 0;
        return FALSE;
    }

    *m_len = h_len;
    return TRUE;
}


/**
 * fbCollectorMessageHeaderNull
 *
 * this is used to process a PDU after it has been read in a message
 * based transport protocol (UDP, SCTP) to adjust the header if
 * needed before sending it to post read fixing.  This version does
 * nothing. NULL transform.
 *
 * @param collector pointer to the collector state structure
 * @param buffer pointer to the message buffer
 * @param b_len length of the buffer passed in
 * @param m_len pointer to the length of the resultant buffer
 * @param err pointer to a GLib error structure
 *
 * @return TRUE (this always works)
 *
 */
static gboolean    fbCollectorMessageHeaderNull (
    fbCollector_t               *collector __attribute__((unused)),
    uint8_t                     *buffer __attribute__((unused)),
    size_t                      b_len,
    uint16_t                    *m_len,
    GError                      **err __attribute__((unused)) )
{
    *m_len = b_len;
    return TRUE;
}

/**
 * fbCollectorUDPMessageHeader
 *
 * this is used to process a PDU after it has been read in a message
 * based transport protocol (UDP, SCTP) to adjust the header if
 * needed before sending it to post read fixing.  This version does
 * nothing. NULL transform.
 *
 * @param collector pointer to the collector state structure
 * @param buffer pointer to the message buffer
 * @param b_len length of the buffer passed in
 * @param m_len pointer to the length of the resultant buffer
 * @param err pointer to a GLib error structure
 *
 * @return TRUE (this always works)
 *
 */
static gboolean    fbCollectorUDPMessageHeader (
    fbCollector_t               *collector,
    uint8_t                     *buffer,
    size_t                      b_len,
    uint16_t                    *m_len,
    GError                      **err __attribute__((unused)) )
{
    *m_len = b_len;

    if (b_len > 16) {
        collector->obdomain = g_ntohl(*(uint32_t *)(buffer + 12));
        /* Update collector time */
        collector->time = time(NULL);
    }

    return TRUE;
}


/**
 * fbCollectorPostProcNull
 *
 * this is used to process a PDU after it has been read in order to transform
 * it, except that this function does _no_ transforms
 *
 * @param collector _not used_
 *
 * @return TRUE (always succesfull)
 *
 */
static gboolean     fbCollectorPostProcNull(
    fbCollector_t   *collector,
    uint8_t         *dataBuf,
    size_t          *bufLen,
    GError          **err)
{
    (void)collector;
    (void)dataBuf;
    (void)bufLen;
    (void)err;

    return TRUE;
}

/**
 * fbCollectorCloseTranslatorNull
 *
 * default function to clean up the translator state, but there is
 * none, and this function does nothing
 *
 * @param collector current collector
 *
 */
static void         fbCollectorCloseTranslatorNull(
    fbCollector_t   *collector)
{
    (void)collector;
    return;
}

/**
 * fbCollectorSessionTimeoutNull
 *
 * default function to clean up timed out UDP sessions.
 * this function does nothing
 *
 * @param collector current collector
 * @param session session that will be timed out
 *
 */
static void        fbCollectorSessionTimeoutNull(
    fbCollector_t     *collector,
    fbSession_t       *session)
{
    (void)collector;
    (void)session;
    return;
}


/*#################################################
 *
 * the rest of the meat of the collector implementation
 *
 *#################################################*/

/**
 * fbCollectorReadFile
 *
 *
 *
 */
static gboolean fbCollectorReadFile(
    fbCollector_t           *collector,
    uint8_t                 *msgbase,
    size_t                  *msglen,
    GError                  **err)
{
    int                     rc;
    uint16_t                h_len;
    gboolean                goodLen;

    /* Read and decode version and length */
    g_assert(*msglen > 4);

    rc = fread(msgbase, 1, 4, collector->stream.fp);
    if (rc > 0) {
        goodLen = collector->coreadLen(collector, (fbCollectorMsgVL_t *)msgbase,
                                        *msglen, &h_len, err);
        if (FALSE == goodLen) return FALSE;
        msgbase += 4;
    } else if (feof(collector->stream.fp)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOF,
                    "End of file");
        return FALSE;
    } else {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "I/O error: %s", strerror(errno));
        return FALSE;
    }

    /* read rest of message */
    rc = fread(msgbase, 1, h_len - 4, collector->stream.fp);
    if (rc > 0) {
        *msglen = rc + 4;
        if (!collector->copostRead(collector, msgbase, msglen, err)) {
            return FALSE;
        }
        return TRUE;
    } else if (feof(collector->stream.fp)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOF,
                    "End of file");
        return FALSE;
    } else {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "I/O error: %s", strerror(errno));
        return FALSE;
    }
}

/**
 * fbCollectorCloseFile
 *
 *
 *
 */
static void fbCollectorCloseFile(
    fbCollector_t   *collector)
{
    if (collector->stream.fp != stdin) {
        fclose(collector->stream.fp);
    }
    collector->active = FALSE;
}

/**
 * fbCollectorAllocFP
 *
 *
 *
 */
fbCollector_t *fbCollectorAllocFP(
    void            *ctx,
    FILE            *fp)
{
    fbCollector_t   *collector = NULL;

    /* Create a new collector */
    collector = g_slice_new0(fbCollector_t);

    /* Fill the collector in */
    collector->ctx = ctx;
    collector->stream.fp = fp;
    collector->bufferedStream = TRUE;
    collector->active = TRUE;
    collector->coread = fbCollectorReadFile;
    collector->copostRead = fbCollectorPostProcNull;
    collector->coreadLen = fbCollectorDecodeMsgVL;
    collector->comsgHeader = fbCollectorMessageHeaderNull;
    collector->cotransClose = fbCollectorCloseTranslatorNull;
    collector->cotimeOut = fbCollectorSessionTimeoutNull;
    collector->translationActive = FALSE;
    collector->rip = -1;
    collector->wip = -1;

    /* All done */
    return collector;
}

/**
 * fbCollectorAllocFile
 *
 *
 *
 */
fbCollector_t *fbCollectorAllocFile(
    void            *ctx,
    const char      *path,
    GError          **err)
{
    fbCollector_t   *collector = NULL;
    FILE            *fp = NULL;

    /* check to see if we're opening stdin */
    if ((strlen(path) == 1) && (path[0] == '-'))
    {
        /* don't open a terminal */
        if (isatty(fileno(stdin))) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "Refusing to open stdin terminal for collection");
            return NULL;
        }

        /* yep, stdin */
        fp = stdin;
    } else {
        /* nope, just a regular file; open it. */
        fp = fopen(path, "r");
    }

    /* check for error */
    if (!fp) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "Couldn't open %s for collection: %s",
                    path, strerror(errno));
        return NULL;
    }

    /* allocate a collector */
    collector = fbCollectorAllocFP(ctx, fp);

    /* set the file close function */
    collector->coclose = fbCollectorCloseFile;

    /* set the default collector function */
    collector->copostRead = fbCollectorPostProcNull;

    /* default translator cleanup function */
    collector->cotransClose = fbCollectorCloseTranslatorNull;

    /* set the default message read length function */
    collector->coreadLen = fbCollectorDecodeMsgVL;

    /* set the default message header transform function */
    collector->comsgHeader = fbCollectorMessageHeaderNull;

    /* set the default session timed out function - won't get called */
    collector->cotimeOut = fbCollectorSessionTimeoutNull;

    /* mark the stream if it is a buffered file pointer */
    collector->bufferedStream = TRUE;

    /* set that a input translator is not in use */
    collector->translationActive = FALSE;

    /* since we're not a listener */
    collector->rip = -1;
    collector->wip = -1;

    /* all done */
    return collector;
}

#if FB_ENABLE_SCTP

/**
 * fbCollectorReadSCTP
 *
 *
 *
 */
static gboolean fbCollectorReadSCTP(
    fbCollector_t   *collector,
    uint8_t         *msgbase,
    size_t          *msglen,
    GError          **err)
{
    uint16_t                msgSize;
    struct sockaddr         peer;
    socklen_t               peerlen = sizeof(peer);
    struct sctp_sndrcvinfo  sri;
    int                     sctp_flags = 0;
    int                     rc;

    rc = sctp_recvmsg(collector->stream.fd, msgbase, *msglen,
                      &peer, &peerlen, &sri, &sctp_flags);

    if (rc > 0) {
        if (!collector->comsgHeader(collector, msgbase, rc, &msgSize, err)) {
            return FALSE;
        }
        *msglen = msgSize;
        if (!collector->copostRead(collector, msgbase, msglen, err)) {
            return FALSE;
        }
        return TRUE;
    } else if (rc == 0) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOF,
                    "End of file");
        return FALSE;
    } else if (errno == EINTR) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                    "SCTP read interrupt");
        return FALSE;
    } else {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "TCP I/O error: %s", strerror(errno));
        return FALSE;
    }
}
#endif /* FB_ENABLE_SCTP */

static int fbCollectorHandleSelect(
    fbCollector_t   *collector)
{
    fd_set  rdfds;
    int     maxfd;
    int     count;
    int     retVal = 0;
    uint8_t byte;

    g_assert(collector);

    if (collector->rip > collector->stream.fd) {
        maxfd = collector->rip;
    } else {
        maxfd = collector->stream.fd;
    }

    maxfd++;

    FD_ZERO(&rdfds);
    FD_SET(collector->rip, &rdfds);
    FD_SET(collector->stream.fd, &rdfds);

    count = select(maxfd, &rdfds, NULL, NULL, NULL);

    if (count) {
        if (FD_ISSET(collector->stream.fd, &rdfds)) {
            retVal = 0;
        }

        if (FD_ISSET(collector->rip, &rdfds)) {
            read(collector->rip, &byte, sizeof(byte));
            return -1;
        }
        return retVal;
    } else {
        return -1;
    }
}

/**
 * fbCollectorReadTCP
 *
 *
 *
 */
static gboolean fbCollectorReadTCP(
    fbCollector_t   *collector,
    uint8_t         *msgbase,
    size_t          *msglen,
    GError          **err)
{
    int                     rc;
    uint16_t                h_len, rrem;
    gboolean                goodLen;

    /* Read and decode version and length */
    g_assert(*msglen > 4);
    rrem = 4;
    while (rrem) {
        rc = fbCollectorHandleSelect(collector);

        if (rc < 0) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "Interrupted by pipe");
            /* interrupted by pipe read or other error with select*/
            return FALSE;
        }

        rc = read(collector->stream.fd, msgbase, rrem);
        if (rc > 0) {
            rrem -= rc;
            msgbase += rc;
        } else if (rc == 0) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOF,
                        "End of file");
            return FALSE;
        } else if (errno == EINTR) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "TCP read interrupt at message start");
            return FALSE;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "TCP I/O error: %s", strerror(errno));
            return FALSE;
        }
    }
    goodLen = collector->coreadLen(collector,
                                   (fbCollectorMsgVL_t *)(msgbase - 4),
                                   *msglen, &h_len, err);
    if (FALSE == goodLen) return FALSE;

    /* read rest of message */
    rrem = h_len - 4;
    while (rrem) {
        rc = fbCollectorHandleSelect(collector);

        if (rc < 0) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "Interrupted by pipe");
            /* interrupted by pipe read or other error with select*/
            return FALSE;
        }
        rc = read(collector->stream.fd, msgbase, rrem);
        if (rc > 0) {
            rrem -= rc;
            msgbase += rc;
        } else if (rc == 0) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOF,
                        "End of file");
            return FALSE;
        } else if (errno == EINTR) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "TCP read interrupt in message");
            return FALSE;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "TCP I/O error: %s", strerror(errno));
            return FALSE;
        }
    }

    /* Post process, if needed and return message length from header. */
    *msglen = h_len;
    if (!collector->copostRead(collector, msgbase, msglen, err)) {
        return FALSE;
    }
    return TRUE;
}

static void fbCollectorSetUDPSpec(
    fbCollector_t         *collector,
    fbUDPConnSpec_t       *spec)
{

    if (collector->udp_head == NULL) {
        collector->udp_head = spec;
        collector->udp_tail = spec;
    } else if (collector->udp_head != spec) {
        /* don't pick if it's new */
        if (spec->prev || spec->next) {
            /* connect last to next */
            if (spec->prev) {
                spec->prev->next = spec->next;
            }

            /* connect next to last last */
            if (spec->next) {
                spec->next->prev = spec->prev;
            } else {
                collector->udp_tail = spec->prev;
            }

            spec->prev = NULL;
            fbListenerSetPeerSession(collector->listener, spec->session);
        }

        /* now set it in the front */
        spec->next = collector->udp_head;
        collector->udp_head->prev = spec;
        collector->udp_head = spec;
    }
}

static void fbCollectorFreeUDPSpec(
    fbCollector_t          *collector,
    fbUDPConnSpec_t        *spec)
{
    /* let translators release state */
    collector->cotimeOut(collector, spec->session);

    /* don't free the last session, fbufree will do that */
    if (collector->udp_tail != collector->udp_head) {
        fbSessionFree(spec->session);
    }

    if (collector->udp_tail == spec) {
        if (spec->prev) {
            collector->udp_tail = spec->prev;
            spec->prev->next = NULL;
        } else {
            collector->udp_tail = NULL;
        }
    }

    if (collector->multi_session) {
        fbListenerAppFree(collector->listener, spec->ctx);
    }

    g_slice_free(fbUDPConnSpec_t, spec);
}

/**
 * fbCollectorVerifyUDPPeer
 *
 *
 *
 */
static gboolean fbCollectorVerifyUDPPeer(
    fbCollector_t   *collector,
    struct sockaddr *from,
    socklen_t       fromlen,
    GError          **err)
{
    fbUDPConnSpec_t    *udp = collector->udp_head;
    gboolean           found = FALSE;

    /* stash the address if we've not seen it before */
    /* compare the address if we have */
    /* appinit should simulate no data (NLREAD) if message is from wrong peer*/

    if (collector->accept_only) {
        if (collector->peer.so.sa_family == from->sa_family) {
            if (from->sa_family == AF_INET) {
                if (memcmp(&(collector->peer.ip4.sin_addr),
                           &(((struct sockaddr_in *)from)->sin_addr),
                           sizeof(struct in_addr)))
                {
                    g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                                "Ignoring message from peer");
                    return FALSE;
                }
            } else if (from->sa_family == AF_INET6) {
                if(memcmp(&(collector->peer.ip6.sin6_addr),
                          &(((struct sockaddr_in6 *)from)->sin6_addr),
                          sizeof(struct in6_addr)))
                {
                    g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                                "Ignoring message from peer");
                    return FALSE;
                }
            }
        }
    } else {
        memcpy(&(collector->peer.so), from,
               (fromlen > sizeof(collector->peer)) ?
               sizeof(collector->peer) : fromlen);
    }

    while (udp) {
        /* loop through and find current one */
        if (udp->obdomain == collector->obdomain) {
            if (!memcmp(&(udp->peer.so), from, udp->peerlen)) {
                /* we have a match - set session */
                fbCollectorSetUDPSpec(collector, udp);
                found = TRUE;
                break;
            }
        }
        udp = udp->next;
    }


    if (!found) {
        udp = g_slice_new0(fbUDPConnSpec_t);
        memcpy(&(udp->peer.so), from, (fromlen > sizeof(udp->peer)) ?
               sizeof(udp->peer) : fromlen);
        udp->peerlen = (fromlen > sizeof(udp->peer)) ? sizeof(udp->peer) : fromlen;
        udp->obdomain = collector->obdomain;
        /* create a new session */
        udp->session = fbListenerSetPeerSession(collector->listener, NULL);
        fbCollectorSetUDPSpec(collector, udp);

        /* call app init for new UDP connection*/
        if (collector->multi_session) {
            if (!fbListenerCallAppInit(collector->listener, udp, err)) {
                udp->last_seen = collector->time;
                udp->reject = TRUE;
                return FALSE;
            }
        } else {
            /* backwards compatibility -> need to associate the ctx with all
               sessions */
            udp->ctx = collector->ctx;
        }
    } else {
        if (udp->reject) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "Rejecting previously rejected connection");
            return FALSE;
        }
    }

    collector->ctx = udp->ctx;
    udp->last_seen = collector->time;

    while (collector->udp_tail &&
           (difftime(collector->time, collector->udp_tail->last_seen) >
            FB_UDP_TIMEOUT))
    {
        /* timeout check */
        fbCollectorFreeUDPSpec(collector, collector->udp_tail);
    }


    return TRUE;
}

static int fbCollectorHandleSelectUDP(
    fbCollector_t   *collector)
{
    fd_set  rdfds;
    int     maxfd;
    int     count;
    int     retVal = 0;
    uint8_t byte;

    g_assert(collector);

    if (collector->rip > collector->stream.fd) {
        maxfd = collector->rip;
    } else {
        maxfd = collector->stream.fd;
    }

    maxfd++;

    FD_ZERO(&rdfds);
    FD_SET(collector->rip, &rdfds);
    FD_SET(collector->stream.fd, &rdfds);

    count = select(maxfd, &rdfds, NULL, NULL, NULL);

    if (count) {
        if (FD_ISSET(collector->stream.fd, &rdfds)) {
            retVal = 0;
        }

        if (FD_ISSET(collector->rip, &rdfds)) {
            read(collector->rip, &byte, sizeof(byte));
          return -1;
        }
        return retVal;
    } else {
        return -1;
    }
}


/**
 * fbCollectorReadUDP
 *
 *
 *
 */
static gboolean fbCollectorReadUDP(
    fbCollector_t   *collector,
    uint8_t         *msgbase,
    size_t          *msglen,
    GError          **err)
{
    uint16_t        msgSize = 0;
    ssize_t         recvlen = 0;
    int             rc;
    union {
        struct sockaddr         so;
        struct sockaddr_in      ip4;
        struct sockaddr_in6     ip6;
    }                           peer;
    socklen_t                   peerlen;

    memset(&peer, 0, sizeof(peer));

    rc = fbCollectorHandleSelect(collector);

    if (rc < 0) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "Interrupted by pipe");
        /* interrupted by pipe read or other error with select*/
        return FALSE;
    }

    peerlen = sizeof(peer);
    recvlen = recvfrom(collector->stream.fd, msgbase, *msglen, 0,
                       (struct sockaddr *)&peer, &peerlen);


    if (peer.so.sa_family == AF_INET && !collector->stream_by_port) {
        peer.ip4.sin_port = 0;
    } else if (peer.so.sa_family == AF_INET6) {
        if (!collector->stream_by_port) peer.ip6.sin6_port = 0;
        peer.ip6.sin6_flowinfo = 0;
        peer.ip6.sin6_scope_id = 0;
    }

    if (!collector->comsgHeader(collector, msgbase, recvlen, &msgSize, err)) {
        return FALSE;
    }

    if (msgSize > 0) {
        *msglen = msgSize;
        /** Fixed this to do the right thing.  We now map ip addresses
         * and observation domains to sessions.  If accept-only is set
         * on the collector, we'll only return TRUE if the ips match.
         * We will return NL_READ if FALSE, and the app using fixbuf
         * should ignore error codes = NL_READ.**/

        /* this will only veto if we set accept from explicitly*/
        if (!fbCollectorVerifyUDPPeer(collector, &(peer.so), peerlen, err)) {
            return FALSE;
        }
        if (!collector->copostRead(collector, msgbase, msglen, err)) {
            return FALSE;
        }
        return TRUE;
    } else if (errno == EINTR || errno == EWOULDBLOCK) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "UDP read interrupt or timeout");
        return FALSE;
    } else {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "UDP I/O error: %s", strerror(errno));
        return FALSE;
    }
}

/**
 * fbCollectorCloseSocket
 *
 *
 *
 */
static void fbCollectorCloseSocket(
    fbCollector_t   *collector)
{
    close(collector->stream.fd);
    if (collector->rip != -1)
    {
        close(collector->rip);
        collector->rip = -1;
    }

    if (collector->wip != -1)
    {
        close(collector->wip);
        collector->wip = -1;
    }

    collector->active = FALSE;
}

/**
 * fbCollectorAllocSocket
 *
 *
 *
 */
fbCollector_t *fbCollectorAllocSocket(
    fbListener_t    *listener,
    void            *ctx,
    int             fd,
    struct sockaddr *peer,
    size_t          peerlen)
{
    fbCollector_t  *collector   = NULL;
    fbConnSpec_t   *spec        = fbListenerGetConnSpec(listener);
    int             pfd[2];

    /* Create a new collector */
    collector = g_slice_new0(fbCollector_t);

    /* Fill it in */
    collector->listener = listener;
    collector->ctx = ctx;
    collector->stream.fd = fd;
    collector->bufferedStream = FALSE;
    collector->active = TRUE;
    collector->copostRead = fbCollectorPostProcNull;
    collector->coreadLen = fbCollectorDecodeMsgVL;
    collector->comsgHeader = fbCollectorMessageHeaderNull;
    collector->coclose = fbCollectorCloseSocket;
    collector->cotransClose = fbCollectorCloseTranslatorNull;
    collector->cotimeOut = fbCollectorSessionTimeoutNull;
    collector->translationActive = FALSE;
    collector->multi_session = FALSE;

    /* Create interrupt pipe */
    if (pipe(pfd)) {
        return NULL;
    }
    collector->rip = pfd[0];
    collector->wip = pfd[1];

    if (peerlen) {
        memcpy(&(collector->peer.so), peer,
               (peerlen > sizeof(collector->peer)) ?
                    sizeof(collector->peer) : peerlen);
    }

    /* Select a reader function */
    switch(spec->transport) {
#if FB_ENABLE_SCTP
    case FB_SCTP:
        collector->coread = fbCollectorReadSCTP;
        break;
#endif
    case FB_TCP:
        collector->coread = fbCollectorReadTCP;
        break;
    case FB_UDP:
        collector->coread = fbCollectorReadUDP;
        collector->comsgHeader = fbCollectorUDPMessageHeader;
        break;
    default:
        g_assert_not_reached();
    }

    /* All done */
    return collector;
}

#if HAVE_OPENSSL

/**
 * fbCollectorReadTLS
 *
 *
 *
 */
static gboolean fbCollectorReadTLS(
    fbCollector_t   *collector,
    uint8_t         *msgbase,
    size_t          *msglen,
    GError          **err)
{
    int                     rc;
    uint16_t                h_len, rrem;
    gboolean                rv;

    /* Read and decode version and length */
    g_assert(*msglen > 4);
    rrem = 4;
    while (rrem) {
        rc = SSL_read(collector->ssl, msgbase, rrem);
        if (rc > 0) {
            rrem -= rc;
            msgbase += rc;
        } else if (rc == 0) {
            /* FIXME this isn't _quite_ robust but it's good enough for now.
               we'll fix this when we do TLS/TCP stress testing. */
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOF,
                        "TLS connection shutdown");
            return FALSE;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "TLS I/O error at message start: %s",
                        ERR_error_string(ERR_get_error(), NULL));
            while (ERR_get_error());
            return FALSE;
        }
    }
    rv = collector->coreadLen(collector,
                              (fbCollectorMsgVL_t *)(msgbase - 4), *msglen, &h_len, err);
    if (rv == FALSE) return FALSE;

    /* read rest of message */
    rrem = h_len - 4;
    while (rrem) {
        rc = SSL_read(collector->ssl, msgbase, rrem);
        if (rc > 0) {
            rrem -= rc;
            msgbase += rc;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "TLS I/O error in message: %s",
                        ERR_error_string(ERR_get_error(), NULL));
            while (ERR_get_error());
            return FALSE;
        }
    }

    /* All done. Return message length from header. */
    *msglen = h_len;
    return TRUE;
}

/**
 * fbCollectorCloseTLS
 *
 *
 *
 */
static void fbCollectorCloseTLS(
    fbCollector_t   *collector)
{
    SSL_shutdown(collector->ssl);
    SSL_free(collector->ssl);
    if (collector->rip != -1)
    {
        close(collector->rip);
        collector->rip = -1;
    }

    if (collector->wip != -1)
    {
        close(collector->wip);
        collector->wip = -1;
    }

    collector->active = FALSE;
}

/**
 * fbCollectorOpenTLS
 *
 *
 *
 */
static gboolean fbCollectorOpenTLS(
    fbCollector_t   *collector,
    GError          **err)
{
    fbConnSpec_t    *spec = fbListenerGetConnSpec(collector->listener);
    BIO             *conn;
    gboolean        ok = TRUE;

    /* Initialize SSL context if necessary */
    if (!spec->vssl_ctx) {
        if (!fbConnSpecInitTLS(spec, TRUE, err)) {
            return FALSE;
        }
    }

    /* wrap a stream BIO around the opened socket */
    if (!(conn = BIO_new_socket(collector->stream.fd, 1))) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't wrap socket for TLS: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* create SSL socket */
    if (!(collector->ssl = SSL_new((SSL_CTX *)spec->vssl_ctx))) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldnt create TLS socket: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* accept SSL connection */
    SSL_set_accept_state(collector->ssl);
    SSL_set_bio(collector->ssl, conn, conn);
    SSL_set_mode(collector->ssl, SSL_MODE_AUTO_RETRY);
    if (SSL_accept(collector->ssl) <= 0) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't accept on connected TLS socket: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* FIXME do post-connection verification */

end:
    if (!ok) {
        collector->active = FALSE;
        if (collector->ssl) {
            SSL_free(collector->ssl);
            collector->ssl = NULL;
        } else if (conn) {
            BIO_vfree(conn);
        }
    }
    return ok;
}

#if HAVE_OPENSSL_DTLS

/**
 * fbCollectorOpenDTLS
 *
 *
 *
 */
static gboolean fbCollectorOpenDTLS(
    fbCollector_t   *collector,
    GError          **err)
{
    fbConnSpec_t    *spec = fbListenerGetConnSpec(collector->listener);
    BIO             *conn;
    gboolean        ok = TRUE;

    /* Initialize SSL context if necessary */
    if (!spec->vssl_ctx) {
        if (!fbConnSpecInitTLS(spec, TRUE, err)) {
            return FALSE;
        }
    }

    /* wrap a stream BIO around the opened socket */
    if (!(conn = BIO_new_dgram(collector->stream.fd, 1))) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't wrap socket for TLS: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* create SSL socket */
    if (!(collector->ssl = SSL_new((SSL_CTX *)spec->vssl_ctx))) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldnt create TLS socket: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* Enable cookie exchange */
    SSL_set_options(collector->ssl, SSL_OP_COOKIE_EXCHANGE);

    /* accept SSL connection */
    SSL_set_bio(collector->ssl, conn, conn);
    SSL_set_accept_state(collector->ssl);
    SSL_set_mode(collector->ssl, SSL_MODE_AUTO_RETRY);
    if (SSL_accept(collector->ssl) <= 0) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't accept on connected TLS socket: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* FIXME do post-connection verification */

end:
    if (!ok) {
        collector->active = FALSE;
        if (collector->ssl) {
            SSL_free(collector->ssl);
            collector->ssl = NULL;
        } else if (conn) {
            BIO_vfree(conn);
        }
    }
    return ok;
}

#endif /* HAVE_OPENSSL_DTLS */

/**
 * fbCollectorAllocTLS
 *
 *
 *
 */
fbCollector_t *fbCollectorAllocTLS(
    fbListener_t    *listener,
    void            *ctx,
    int             fd,
    struct sockaddr *peer,
    size_t          peerlen,
    GError          **err)
{
    gboolean        ok = TRUE;
    fbCollector_t   *collector = NULL;
    fbConnSpec_t    *spec = fbListenerGetConnSpec(listener);

    /* Create a new collector */
    collector = g_slice_new0(fbCollector_t);

    /* Fill it in */
    collector->listener = listener;
    collector->ctx = ctx;
    collector->stream.fd = fd;
    collector->bufferedStream = FALSE;
    collector->active = TRUE;
    collector->copostRead = fbCollectorPostProcNull;
    collector->coreadLen = fbCollectorDecodeMsgVL;
    collector->comsgHeader = fbCollectorMessageHeaderNull;
    collector->coread = fbCollectorReadTLS;
    collector->coclose = fbCollectorCloseTLS;
    collector->cotransClose = fbCollectorCloseTranslatorNull;
    collector->cotimeOut = fbCollectorSessionTimeoutNull;
    collector->translationActive = FALSE;
    if (peerlen) {
        memcpy(&(collector->peer.so), peer,
               (peerlen > sizeof(collector->peer)) ?
                    sizeof(collector->peer) : peerlen);
    }


    /* Do TLS accept atop opened socket */
    switch (spec->transport) {
    case FB_TLS_TCP:
        ok = fbCollectorOpenTLS(collector, err);
        break;
#if HAVE_OPENSSL_DTLS
    case FB_DTLS_UDP:
#if HAVE_OPENSSL_DTLS_SCTP
    case FB_DTLS_SCTP:
#endif
        ok = fbCollectorOpenDTLS(collector, err);
    break;
#endif
    default:
        g_assert_not_reached();
    }

    /* Nuke collector on TLS setup error */
    if (!ok) {
        g_slice_free(fbCollector_t, collector);
        return NULL;
    }

    /* All done */
    return collector;
}

#endif /* HAVE_OPENSSL */

#ifdef HAVE_SPREAD

static gboolean fbCollectorSpreadOpen(
    fbCollector_t *collector,
    GError **err )
{
    int ret;
    int i = 0;
    char grp[MAX_GROUP_NAME];
    fbSpreadSpec_t *spread = collector->stream.spread;

    if (!spread->daemon)
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread daemon name cannot be null" );
        return FALSE;
    }
    if (!spread->daemon[0])
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread daemon name cannot be empty" );
        return FALSE;
    }
    /*if (strnlen( spread->daemon, 262 ) > 261)*/
    if ( !(memchr( spread->daemon, 0, 261)) )
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread daemon name too long" );
        return FALSE;
    }
    if (!spread->groups)
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread groups cannot be null" );
        return FALSE;
    }
    if (!spread->groups[0].name[0])
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread groups cannot be empty" );
        return FALSE;
    }
    if (!spread->session)
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread session cannot be null" );
        return FALSE;
    }

    ret = SP_connect( spread->daemon, 0, 0, 0, &(spread->recv_mbox),
                      spread->privgroup );

    if (ret != ACCEPT_SESSION)
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "error connecting to Spread daemon %s: %s",
                     spread->daemon, fbConnSpreadError( ret ) );
        return FALSE;
    }

    // mark it active here, fbCollectorFree() will need to disconnect
    collector->active = TRUE;

    for (i = 0; i < spread->num_groups; ++i)
    {
        ret = SP_join( spread->recv_mbox, spread->groups[i].name);
        if (ret)
        {
            g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                         "error joining to Spread data group %s: %s",
                         spread->groups[i].name, fbConnSpreadError( ret ) );
            return FALSE;
        }
    }

    /* now that we have joined the data plane group, join the
     control/template plane group to signal exporters that
     we need the templates for this group. */

    for (i = 0; i < spread->num_groups; ++i)
    {
        memset( grp, 0, sizeof( grp ) );
        strncpy( grp, spread->groups[i].name, sizeof( grp) - 2 );
        strcat( grp, "T" );
        ret = SP_join( spread->recv_mbox, grp );

        if (ret) {
            g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                       "error joining to Spread control/template group %s: %s",
                         spread->groups[i].name, fbConnSpreadError( ret ) );
            return FALSE;
        }
    }

    return TRUE;
}

/* There is no good way to deal with sequence numbers in Spread.
 * This was added to return False if the collector receives
 * a message where it is not the first group listed in msg.
 * This is because the exporter only looks at the first group
 * when deciding what sequence number to export */

static gboolean fbCollectorSpreadPostProc(
    fbCollector_t *collector,
    uint8_t       *buffer,
    size_t        *b_len,
    GError        **err)
{

    if (fbCollectorTestGroupMembership(collector, 0)) {
        return TRUE;
    }
    (void) collector;
    (void) buffer;
    (void) b_len;
    (void) err;

    return FALSE;
}

int fbCollectorGetSpreadReturnGroups(
    fbCollector_t *collector,
    char *groups[] )
{
    int loop = 0;
    fbSpreadSpec_t *spread = collector->stream.spread;

    for ( loop = 0; loop < spread->recv_num_groups; loop++){
        groups[loop] = spread->recv_groups[loop].name;
    }

    return spread->recv_num_groups;
}

static gboolean fbCollectorSpreadRead(
    fbCollector_t *collector,
    uint8_t *msgbase,
    size_t *msglen,
    GError **err )
{
    fbSpreadSpec_t *spread = collector->stream.spread;

    service         service_type = 0;
    char            sender[MAX_GROUP_NAME];
    int16           mess_type = 0;
    int             endian_mismatch;
    int             no_mess = 1;
    int             ret;

    do
    {
        ret = SP_receive( spread->recv_mbox, &service_type, sender,
                          spread->recv_max_groups,
                          &(spread->recv_num_groups),
                          (char (*)[])spread->recv_groups,
                          &mess_type, &endian_mismatch, *msglen,
                          (char *)msgbase );

        if (spread->recv_exit) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_EOF,
                        "End of file: spread shut down or was not connected");
            return FALSE;
        }

        if (ret < 0) {
            if (ret == GROUPS_TOO_SHORT) {
                g_free(spread->recv_groups);
                spread->recv_max_groups = -spread->recv_num_groups;
                spread->recv_groups = g_new0( sp_groupname_t,
                                              spread->recv_max_groups );
            } else if (ret == BUFFER_TOO_SHORT) {
                *msglen = -endian_mismatch;
                g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_EOM,
                             "msglen too small (%zd required)", *msglen );
                return FALSE;
            } else if ((ret == CONNECTION_CLOSED) || (ret == ILLEGAL_SESSION))
            {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                            "End of file: %s", fbConnSpreadError(ret));
                return FALSE;
            } else {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                            "error(%d) receiving Spread message: %s", ret,
                            fbConnSpreadError(ret));

                *msglen = 0;
                return FALSE;
            }
        } else {
            *msglen = ret;
            no_mess = 0;
        }

    } while (no_mess);

    return TRUE;
}



static void fbCollectorSpreadClose(
    fbCollector_t *collector )
{
    if (collector->active) {
        SP_disconnect( collector->stream.spread->recv_mbox );
    }
    collector->active = FALSE;
}

fbCollector_t *fbCollectorAllocSpread(
    void *ctx,
    fbSpreadParams_t *params,
    GError **err )
{
    fbCollector_t *collector = g_slice_new( fbCollector_t );
    memset( collector, 0, sizeof( fbCollector_t ) );

    collector->ctx = ctx;
    collector->stream.spread = fbConnSpreadCopy( params );
    collector->bufferedStream = FALSE;
    collector->active = FALSE;
    collector->spread_active = 1;

    collector->coread = fbCollectorSpreadRead;
    collector->coreadLen = fbCollectorDecodeMsgVL;  /* after SCTP */
    collector->copostRead = fbCollectorSpreadPostProc; /* after SCTP */
    collector->comsgHeader = fbCollectorMessageHeaderNull; /* after SCTP */
    collector->coclose = fbCollectorSpreadClose;
    collector->cotransClose = fbCollectorCloseTranslatorNull; /* after SCTP */
    collector->cotimeOut = fbCollectorSessionTimeoutNull;

    collector->translationActive = FALSE;

    if (!fbCollectorSpreadOpen( collector, err )) {
        fbCollectorFree( collector );
        return 0;
    }

    return collector;
}

gboolean fbCollectorTestGroupMembership(
    fbCollector_t *collector,
    int            group_offset)
{
    int loop;
    fbSpreadSpec_t *spread = NULL;

    if (!collector->spread_active) {
        return TRUE;
    }

    spread = collector->stream.spread;
    for (loop = 0; loop < spread->num_groups; loop++) {
        if (strcmp(spread->recv_groups[group_offset].name,
                   spread->groups[loop].name) == 0)
        {
            fbSessionSetGroup(spread->session,
                              (char *)spread->recv_groups[group_offset].name);
            return TRUE;
        }
    }

    return FALSE;
}


#endif /* HAVE_SPREAD */

/**
 * fbCollectMessage
 *
 *
 *
 */
gboolean        fbCollectMessage(
    fbCollector_t   *collector,
    uint8_t         *msgbase,
    size_t          *msglen,
    GError          **err)
{
    /* Ensure stream is open */
    if (!collector->active) return FALSE;

    /* Attempt to read message */
    if (collector->coread(collector, msgbase, msglen, err)) return TRUE;

    /* Read failure; signal error */
    return FALSE;
}

/**
 * fbCollectorGetContext
 *
 *
 *
 */
void          *fbCollectorGetContext(
    fbCollector_t   *collector)
{
    return collector->ctx;
}


/**
 * fbCollectorHasTranslator
 *
 * use this is check to see if a protocol translation
 * is in use for this collector.  Needed by the transcode
 * and IPFIX machinery to get rid of some error checks
 * which no longer apply.
 *
 * @param collector pointer to the collector state struct
 *
 * @return TRUE if a translator is in use, FALSE otherwise
 */
gboolean        fbCollectorHasTranslator(
    fbCollector_t   *collector)
{
    return collector->translationActive;
}

/**
 * fbCollectorGetFD
 *
 *
 *
 */
int             fbCollectorGetFD(
    fbCollector_t   *collector)
{
    return collector->stream.fd;
}

/**
 * fbCollectorClose
 *
 *
 *
 */
void            fbCollectorClose(
    fbCollector_t   *collector)
{
    if (collector->active && collector->coclose) collector->coclose(collector);

    if (collector->listener) {
        fbListenerRemove(collector->listener, collector->stream.fd);
    }
}

/**
 * fbCollectorFree
 *
 *
 *
 */
void            fbCollectorFree(
    fbCollector_t   *collector)
{
    if (!collector->multi_session) {
        fbListenerAppFree(collector->listener, collector->ctx);
    }
    collector->cotransClose(collector);
    fbCollectorClose(collector);
    #ifdef HAVE_SPREAD
    if (collector->coclose == fbCollectorSpreadClose)
        fbConnSpreadFree( collector->stream.spread );
    #endif
    while (collector->udp_tail) {
        fbCollectorFreeUDPSpec(collector, collector->udp_tail);
    }

    g_slice_free(fbCollector_t, collector);
}


/**
 * fbCollectorClearTranslator
 *
 * @param collector the collector on which to remove
 *        the translator
 *
 * @return TRUE on success, FALSE on failure
 */
gboolean    fbCollectorClearTranslator(
    fbCollector_t   *collector,
    GError          **err __attribute__((unused)) )
{
    collector->cotransClose(collector);

    return TRUE;
}


/**
 * fbCollectorSetTranslator
 *
 * this sets the collector input to any
 * given translator
 *
 * @param collector the collector to apply the protocol
 *        convertor to
 * @param postProcFunc a function called after the read
 *        to do any post processing/conversion to turn
 *        the buffer into an IPFIX buffer
 * @param vlMessageFunc function to determine the
 *        amount needed to complete the next read
 * @param headerFunc function to transform the header after
 *        a block read before it is sent to the
 *        postProcFunc (called when vlMessageFunc isn't)
 * @param trCloseFunc if anything is needed to be cleaned
 *        up in the translator when a collector is closed
 *        this function will be called before the collector
 *        is closed
 * @param timeOutFunc when UDP sessions timeout, this function will
 *        clear any state associated with the session.
 * @param opaque a void pointer to hold a translator
 *        specific state structure
 * @param err holds the glib based error message on
 *        error
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
    GError                       **err)
{
    if (NULL != collector->translatorState)
    {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_TRANSMISC,
            "Translator is already set on this collector, "
            "must be cleared first");
        return FALSE;
    }

    collector->copostRead = postProcFunc;
    collector->coreadLen = vlMessageFunc;
    collector->comsgHeader = headerFunc;
    collector->cotransClose = trCloseFunc;
    collector->cotimeOut = timeOutFunc;
    collector->translatorState = opaque;
    collector->translationActive = TRUE;

    return TRUE;
}

struct sockaddr* fbCollectorGetPeer(
    fbCollector_t   *collector)
{
    return (&collector->peer.so);
}

void fbCollectorInterruptSocket(
    fbCollector_t   *collector)
{
    uint8_t     byte = 0xe7;

#if HAVE_SPREAD
    if (collector->spread_active) {
        fbCollectorSpreadClose(collector);
        return;
    }
#endif

    write(collector->wip, &byte, sizeof(byte));
    write(collector->rip, &byte, sizeof(byte));
}

void fbCollectorRemoveListenerLastBuf(
    fBuf_t         *fbuf,
    fbCollector_t  *collector)
{
    /* may not have a listener - esp for spread */
    if (collector->listener) {
        fbListenerRemoveLastBuf(fbuf, collector->listener);
    }
}

uint32_t fbCollectorGetObservationDomain(
    fbCollector_t   *collector)
{
    if (!collector) {
        return 0;
    }

    return collector->obdomain;
}

void fbCollectorSetAcceptOnly(
    fbCollector_t   *collector,
    struct sockaddr *address,
    size_t           address_length)
{
    collector->accept_only = TRUE;

    memcpy(&(collector->peer.so), address,
           (address_length > sizeof(collector->peer)) ?
           sizeof(collector->peer) : address_length);
}

void fbCollectorSetUDPMultiSession(
    fbCollector_t *collector,
    gboolean       multi_session)
{
    collector->multi_session = multi_session;
}

/**
 * netflow v9 spec says:
 * NetFlow Collectors SHOULD use the combination of the source IP
 * address and the Source ID field to separate different export
 * streams originating from the same Exporter.
 *
 * however, some routers make this difficult, so turn this flag
 * on to prevent fixbuf from clearing out the ports before comparing
 * sockaddr structs.
 */
void fbCollectorManageUDPStreamByPort(
    fbCollector_t *collector,
    gboolean       manage_port)
{
    collector->stream_by_port = manage_port;
}
