/*@internal
 *
 * fblistener.c
 * IPFIX Collecting Process connection listener implementation
 *
 * ------------------------------------------------------------------------
 * Copyright (C) 2006-2013 Carnegie Mellon University. All Rights Reserved.
 * ------------------------------------------------------------------------
 * Authors: Brian Trammell
 * ------------------------------------------------------------------------
 * @OPENSOURCE_HEADER_START@
 * Use of the libfixbuf system and related source code is subject to the terms
 * of the following licenses:
 *
 * GNU Lesser GPL (LGPL) Rights pursuant to Version 2.1, February 1999
 * Government Purpose License Rights (GPLR) pursuant to DFARS 252.227.7013
 *
 * NO WARRANTY
 *
 * ANY INFORMATION, MATERIALS, SERVICES, INTELLECTUAL PROPERTY OR OTHER
 * PROPERTY OR RIGHTS GRANTED OR PROVIDED BY CARNEGIE MELLON UNIVERSITY
 * PURSUANT TO THIS LICENSE (HEREINAFTER THE "DELIVERABLES") ARE ON AN
 * "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY
 * KIND, EITHER EXPRESS OR IMPLIED AS TO ANY MATTER INCLUDING, BUT NOT
 * LIMITED TO, WARRANTY OF FITNESS FOR A PARTICULAR PURPOSE,
 * MERCHANTABILITY, INFORMATIONAL CONTENT, NONINFRINGEMENT, OR ERROR-FREE
 * OPERATION. CARNEGIE MELLON UNIVERSITY SHALL NOT BE LIABLE FOR INDIRECT,
 * SPECIAL OR CONSEQUENTIAL DAMAGES, SUCH AS LOSS OF PROFITS OR INABILITY
 * TO USE SAID INTELLECTUAL PROPERTY, UNDER THIS LICENSE, REGARDLESS OF
 * WHETHER SUCH PARTY WAS AWARE OF THE POSSIBILITY OF SUCH DAMAGES.
 * LICENSEE AGREES THAT IT WILL NOT MAKE ANY WARRANTY ON BEHALF OF
 * CARNEGIE MELLON UNIVERSITY, EXPRESS OR IMPLIED, TO ANY PERSON
 * CONCERNING THE APPLICATION OF OR THE RESULTS TO BE OBTAINED WITH THE
 * DELIVERABLES UNDER THIS LICENSE.
 *
 * Licensee hereby agrees to defend, indemnify, and hold harmless Carnegie
 * Mellon University, its trustees, officers, employees, and agents from
 * all claims or demands made against them (and any related losses,
 * expenses, or attorney's fees) arising out of, or relating to Licensee's
 * and/or its sub licensees' negligent use or willful misuse of or
 * negligent conduct or willful misconduct regarding the Software,
 * facilities, or other rights or assistance granted by Carnegie Mellon
 * University under this License, including, but not limited to, any
 * claims of product liability, personal injury, death, damage to
 * property, or violation of any laws or regulations.
 *
 * Carnegie Mellon University Software Engineering Institute authored
 * documents are sponsored by the U.S. Department of Defense under
 * Contract FA8721-05-C-0003. Carnegie Mellon University retains
 * copyrights in all material produced under this contract. The U.S.
 * Government retains a non-exclusive, royalty-free license to publish or
 * reproduce these documents, or allow others to do so, for U.S.
 * Government purposes only pursuant to the copyright license under the
 * contract clause at 252.227.7013.
 *
 * @OPENSOURCE_HEADER_END@
 * ------------------------------------------------------------------------
 */

#define _FIXBUF_SOURCE_
#include <fixbuf/private.h>

#ident "$Id: fblistener.c 18734 2013-02-28 21:04:30Z ecoff_svn $"


/**
 *
 * Understanding socket handling and collector construction within the
 * fixbuf listener:
 *
 * Error handling on connections in fixbuf is very different between
 * TCP and UDP connections.  The reasons behind this are partial
 * tied up within the IPFIX standard and its handling of UDP.
 * But within fixbuf, this needs to be understood in terms of how
 * collector's are created with respect to listener's.
 *
 * For both TCP and UDP, when a listener is created, a listening
 * socket is created with the listener.  (lsock)
 *
 * For UDP, the listener sock (lsock) is the socket used to create
 * the collector.  The collector gets created immediately, and the
 * collector is the structure that is associated with the fBuf
 * structure which actually handles PDU's.
 *
 * For TCP, the case is different.  The listening socket is used
 * primarily for the listenerWait call.  It is used as a socket
 * passed to select waiting for connection establishment.  Then
 * an accept call is made which creates a new socket handle.
 * That socket handle is used is to create the collector, and the
 * lsock handle is left only within the listener.
 *
 * When an error occurs, the normal usage of the API would be
 * to call fBufFree and call listenerWait again.  In the case
 * of TCP this works.  The library will wait for a new connection
 * to the listener lsock and create a new collector from a new
 * socket from the accept call.  For UDP, this will not work, and
 * the library will simply hang.  (Each lsock also has a
 * corresponding set of pipes to detect interrupts) and the select
 * call will simply wait on the read pipe handle.
 *
 *
 */

#define MAX_BUFFER_FREE 100

struct fbListener_st {
    /** Connection specifier for passive socket. */
    fbConnSpec_t                *spec;
    /** Base session. Used for internal templates. */
    fbSession_t                 *session;
    /** UDP Base Session.  Only set for UDP listeners.
     * Since UDP sessions are created at connection time,
     * this holds the first one so we can free it. */
    fbSession_t                 *udp_session;
    /** Last buffer returned by fbListenerWait(). */
    fBuf_t                      *lastbuf;
    /** Passive socket file descriptor. */
    int                         lsock;
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
    /**
     * used to hold the handle to the collector for
     * this listener
     */
    fbCollector_t               *collectorHandle;
    /**
     * File descriptor table.
     * Maps file descriptors to active listener-managed buffer instances.
     */
    GHashTable                  *fdtab;
    /**
     * Application initialization function. Allows the application
     * to bind internal context to a collector, and to reject connections
     * after accept() but before session setup.
     */
    fbListenerAppInit_fn        appinit;
    /** Application free function. Frees storage allocated by appinit. */
    fbListenerAppFree_fn        appfree;
};

typedef struct fbListenerWaitFDSet_st {
    fd_set                      fds;
    int                         maxfd;
    fBuf_t                      *fbuf;
} fbListenerWaitFDSet_t;

/**
 * fbListenerTeardownSocket
 *
 *
 *
 *
 */
static void fbListenerTeardownSocket(
    fbListener_t                *listener)
{
    /* nuke interrupt pipe */
    if (listener->rip != -1) {
        close(listener->rip);
        listener->rip = -1;
    }

    if (listener->wip != -1) {
        close(listener->wip);
        listener->wip = -1;
    }

    /* nuke passive socket */
    if (listener->lsock != -1) {
        close(listener->lsock);
        listener->lsock = -1;
    }
}

/**
 *fbListenerInitSocket
 *
 *
 *
 *
 */
static gboolean fbListenerInitSocket(
    fbListener_t                *listener,
    GError                      **err)
{
    int                         pfd[2];
    struct addrinfo             *ai = NULL;

    /* Create interrupt pipe */
    if (pipe(pfd)) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "fbListener error creating interrupt pipe: %s",
                    strerror(errno));
        return FALSE;
    }
    listener->rip = pfd[0];
    listener->wip = pfd[1];

    /* Look up the passive socket address */
    if (!fbConnSpecLookupAI(listener->spec, TRUE, err)) {
        fbListenerTeardownSocket(listener);
        return FALSE;
    }

    ai = (struct addrinfo *)listener->spec->vai;

    /* Create the passive socket */
    do {
        /*
         * Kludge for SCTP. addrinfo doesn't accept SCTP hints.
         */
#if FB_ENABLE_SCTP
        if ((listener->spec->transport == FB_SCTP) ||
            (listener->spec->transport == FB_DTLS_SCTP)) {
            ai->ai_socktype = SOCK_STREAM;
            ai->ai_protocol = IPPROTO_SCTP;
        }
#endif
        /* Create socket and bind it to the passive address */
        listener->lsock = socket(ai->ai_family, ai->ai_socktype,
                                 ai->ai_protocol);
        if (listener->lsock < 0) continue;
        if (bind(listener->lsock, ai->ai_addr, ai->ai_addrlen) < 0) {
            close(listener->lsock); listener->lsock = -1; continue;
        }

        /* Listen only on socket and sequenced packet sockets */
        if ((ai->ai_socktype == SOCK_STREAM)
#ifdef SOCK_SEQPACKET
            || (ai->ai_socktype == SOCK_SEQPACKET)
#endif
            ) {
            if (listen(listener->lsock, 1) < 0) {
                close(listener->lsock); listener->lsock = -1; continue;
            }
        }
        break;
    } while ((ai = ai->ai_next));

    /* check for no listenable socket */
    if (ai == NULL) {
        fbListenerTeardownSocket(listener);
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't create socket listening to %s:%s: %s",
                    listener->spec->host ? listener->spec->host : "*",
                    listener->spec->svc, strerror(errno));
        return FALSE;
    }


    /* All done. */
    return TRUE;
}

/**
 *fbListenerInitUDPSocket
 *
 *
 *
 *
 */
static gboolean fbListenerInitUDPSocket(
    fbListener_t                *listener,
    GError                      **err)
{
    void                        *ctx = NULL;
    fbCollector_t               *collector = NULL;
    fBuf_t                      *fbuf = NULL;

    /* Simulate accept on UDP socket */

    /* Ask application for context */
    if (listener->appinit) {
        if (!listener->appinit(listener, &ctx, listener->lsock, NULL, 0, err)){
            return FALSE;
        }
    }

    /* Create collector on UDP socket */
    switch (listener->spec->transport) {
    case FB_UDP:
        collector = fbCollectorAllocSocket(listener, ctx,
                                           listener->lsock, NULL, 0);
        break;
#if HAVE_OPENSSL_DTLS
    case FB_DTLS_UDP:
        collector = fbCollectorAllocTLS(listener, ctx,
                                        listener->lsock, NULL, 0, err);
        break;
#endif
    default:
        g_assert_not_reached();
    }

    /* Check for collector alloc error */
    if (!collector) return FALSE;

    /* Create a buffer with a cloned session around the collector */
    fbuf = fBufAllocForCollection(fbSessionClone(listener->session),collector);

    /* Add collector to the file descriptor table */
    g_hash_table_insert(listener->fdtab,
                        GINT_TO_POINTER(listener->lsock), fbuf);

    /* No more passive socket */
    listener->lsock = -1;

    /* store this session so we can free it later */
    listener->udp_session = fBufGetSession(fbuf);

    /* store the handle to the collector */
    listener->collectorHandle = collector;
    /* All done. */
    return TRUE;
}

/**
 *fbListenerAlloc
 *
 *
 *
 *
 */
fbListener_t *fbListenerAlloc(
    fbConnSpec_t                *spec,
    fbSession_t                 *session,
    fbListenerAppInit_fn        appinit,
    fbListenerAppFree_fn        appfree,
    GError                      **err)
{
    fbListener_t                *listener = NULL;
    gboolean                    ownSocket;

    if (spec) {
        ownSocket = FALSE;
    } else {
        ownSocket = TRUE;
    }

    /* Allocate a new listener */
    listener = g_slice_new0(fbListener_t);

    /* -1 for file descriptors means no fd */
    listener->lsock = -1;
    listener->rip = -1;
    listener->wip = -1;

    if (ownSocket) { /* user handling own socket creation and connections */
        listener->spec = NULL;
    } else {
        listener->spec = fbConnSpecCopy(spec);
    }
    /* Fill in what we can */
    listener->session = session;
    listener->appinit = appinit;
    listener->appfree = appfree;

    /* allocate file descriptor table */
    listener->fdtab = g_hash_table_new(g_direct_hash, g_direct_equal);

    if (!ownSocket) {
        /* Do transport-specific initialization */
        switch (spec->transport) {
#if FB_ENABLE_SCTP
          case FB_SCTP:
#if HAVE_OPENSSL_DTLS_SCTP
          case FB_DTLS_SCTP:
#endif
#endif
          case FB_TCP:
#if HAVE_OPENSSL
          case FB_TLS_TCP:
#endif
            if (!fbListenerInitSocket(listener, err)) {
                goto err;
            }
            break;
          case FB_UDP:
#if HAVE_OPENSSL_DTLS
          case FB_DTLS_UDP:
#endif
            /* FIXME this may leak on socket setup error for UDP. */
            if (fbListenerInitSocket(listener, err)) {
                if (!fbListenerInitUDPSocket(listener, err)) {
                    fbListenerTeardownSocket(listener);
                    goto err;
                }
            } else {
                goto err;
            }

            break;
          default:
#ifndef FB_ENABLE_SCTP
            if (spec->transport == FB_SCTP || spec->transport == FB_DTLS_SCTP){
                g_error("Libfixbuf not enabled for SCTP Transport. "
                        " Run configure with --with-sctp");
            }
#endif
            if (spec->transport == FB_TLS_TCP ||
                spec->transport == FB_DTLS_SCTP ||
                spec->transport == FB_DTLS_UDP)
            {
                g_error("Libfixbuf not enabled for this mode of transport. "
                        " Run configure with --with-openssl");
            }
        }
    }

    /* Return the initialized listener */
    return listener;

err:
    if (listener) {
        if (listener->fdtab) {
            g_hash_table_destroy(listener->fdtab);
        }

        g_slice_free(fbListener_t, listener);
    }

    /* No listener */
    return NULL;
}


/**
 * fbListenerFreeBuffer
 *
 *
 *
 *
 */
static void   fbListenerFreeBuffer(
    void                        *vfd __attribute__((unused)),
    fBuf_t                      *fbuf,
    /*    void                        *vignore __attribute__((unused)) )*/
    fBuf_t                      **lfbuf)
{
    /* free the buffer; this will close the socket. */
    /*    fBufFree(fbuf);*/
    /* we can't change the hash table while we are looping through it */
    *lfbuf = fbuf;
    lfbuf++;
}

/**
 * fbListenerAppFree
 *
 *
 */

void fbListenerAppFree(
    fbListener_t               *listener,
    void                       *ctx)
{
    if (listener) {
        if (listener->appfree) {
            (listener->appfree)(ctx);
        }
    }
}


/**
 *fbListenerFree
 *
 *
 *
 *
 */
void            fbListenerFree(
    fbListener_t                *listener)
{
    fBuf_t                     *tfbuf[MAX_BUFFER_FREE+1];
    fBuf_t                     *lfbuf = NULL;
    fbSession_t                *session = NULL;
    int                        loop = 0;

    while (loop < MAX_BUFFER_FREE) {
        tfbuf[loop] = NULL;
        loop++;
    }

    /* shut down passive socket */
    fbListenerTeardownSocket(listener);

    /* free any open buffers we may have */
    g_hash_table_foreach(listener->fdtab,
                        (GHFunc)fbListenerFreeBuffer, tfbuf);

    loop = 0;
    lfbuf = tfbuf[0];
    /* free first session */
    if (listener->udp_session) {
        /* we need to get the session set on the fBuf - it should be the
           same as udp_session in the case that we haven't received anything*/
        session = fBufGetSession(lfbuf);
        if (listener->udp_session != session) {
            fbSessionFree(listener->udp_session);
        }
    }

    while (lfbuf && loop < MAX_BUFFER_FREE) {
        fBufFree(lfbuf);
        loop++;
        lfbuf = tfbuf[loop];
    }
    /* free the listener table */
    g_hash_table_destroy(listener->fdtab);

    /* free the connection specifier */
    fbConnSpecFree(listener->spec);

    /* free the listener itself */
    g_slice_free(fbListener_t, listener);
}

/**
 *fbListenerWaitAddFD
 *
 *
 *
 *
 */
static void   fbListenerWaitAddFD(
    void                        *vfd,
    void                        *vignore __attribute__((unused)),
    fbListenerWaitFDSet_t       *lfdset)
{
    int                         fd = GPOINTER_TO_INT(vfd);

    FD_SET(fd,&(lfdset->fds));
    if (fd > lfdset->maxfd) lfdset->maxfd = fd;
}

/**
 * fbListenerWaitSearch
 *
 *
 *
 *
 */
static void   fbListenerWaitSearch(
    void                        *vfd,
    void                        *fbuf,
    fbListenerWaitFDSet_t       *lfdset)
{
    int                         fd = GPOINTER_TO_INT(vfd);

    if (FD_ISSET(fd,&(lfdset->fds))) {
        lfdset->fbuf = fbuf;
    }
}


/**
 * fbListenerWaitAccept
 *
 *
 *
 *
 */
static fBuf_t *fbListenerWaitAccept(
    fbListener_t                *listener,
    GError                      **err)
{
    int                         asock;
    union {
        struct sockaddr         so;
        struct sockaddr_in      ip4;
        struct sockaddr_in6     ip6;
    }                           peer;
    socklen_t                   peerlen;
    void                        *ctx = NULL;
    fbCollector_t               *collector = NULL;
    fBuf_t                      *fbuf = NULL;


    /* Accept the connection */
    peerlen = sizeof(peer);
    asock = accept(listener->lsock, &(peer.so), &peerlen);
    if (asock < 0) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "listener accept error: %s",
                    strerror(errno));
        return NULL;
    }

    /* Okay, we have a socket. Ask the application for context. */
    if (listener->appinit) {

        if (!listener->appinit(listener, &ctx, asock,
                               &(peer.so), peerlen, err)) {
            close(asock);
            return NULL;
        }
    }

    /* Create a collector as appropriate */
    switch (listener->spec->transport) {
#if FB_ENABLE_SCTP
    case FB_SCTP:
#endif
    case FB_TCP:
        collector = fbCollectorAllocSocket(listener, ctx, asock,
                                           &(peer.so), peerlen);
        break;
#if HAVE_OPENSSL
#if HAVE_OPENSSL_DTLS_SCTP
    case FB_DTLS_SCTP:
#endif
    case FB_TLS_TCP:
        collector = fbCollectorAllocTLS(listener, ctx, asock,
                                        &(peer.so), peerlen, err);
        break;
#endif
    default:
        g_assert_not_reached();
    }

    /* Check for collector creation error */
    if (!collector) return NULL;

    /* Create a buffer with a cloned session around the collector */
    fbuf = fBufAllocForCollection(fbSessionClone(listener->session), collector);

    /* Make the buffer automatic */
    fBufSetAutomaticMode(fbuf, TRUE);

    /* Add buffer to the file descriptor table */
    g_hash_table_insert(listener->fdtab, GINT_TO_POINTER(asock), fbuf);

    /* store the collector handle */
    listener->collectorHandle = collector;
    /* All done. */
    return fbuf;
}

/**
 * fbListenerRemove
 *
 *
 *
 *
 */
void fbListenerRemove(
    fbListener_t        *listener,
    int                 fd)
{
    /* remove buffer from fd */
    g_hash_table_remove(listener->fdtab, GINT_TO_POINTER(fd));
}

/**
 * fbListenerWait
 *
 *
 *
 *
 */
fBuf_t *fbListenerWait(
    fbListener_t                *listener,
    GError                      **err)
{
    fbListenerWaitFDSet_t       lfdset;
    uint8_t                     byte;
    int                         rc;

    /* set up the select call... */
    FD_ZERO(&lfdset.fds);
    lfdset.maxfd = 0;
    /* interrupt pipe read end */

    fbListenerWaitAddFD(GINT_TO_POINTER(listener->rip), NULL, &lfdset);
    /* listener socket if available */
    if (listener->lsock >= 0) {
        fbListenerWaitAddFD(GINT_TO_POINTER(listener->lsock), NULL, &lfdset);
    }
    /* any open collectors we may have */
    g_hash_table_foreach(listener->fdtab,
                        (GHFunc)fbListenerWaitAddFD, &lfdset);

    /* wait for data available on one of our file descriptors */
    rc = select(lfdset.maxfd + 1, &lfdset.fds, NULL, NULL, NULL);
    if (rc < 0) {
        if (errno == EINTR) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "Interrupted listener wait");
            return NULL;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "listener wait error: %s",
                        strerror(errno));
            return NULL;
        }
    }

    /* handle interrupt pipe read end */
    if (FD_ISSET(listener->rip, &lfdset.fds)) {
        /* consume and ignore return */
        read(listener->rip, &byte, sizeof(byte));
        /* throw error */
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                    "External interrupt on pipe");
        return NULL;
    }

    /* handle any pending accept, return the accepted buffer immediately. */
    if (listener->lsock >= 0 &&
        FD_ISSET(listener->lsock, &lfdset.fds)) {
        lfdset.fbuf = fbListenerWaitAccept(listener, err);
        if (!lfdset.fbuf) return NULL;
        listener->lastbuf = lfdset.fbuf;
        return lfdset.fbuf;
    }

    /* see if preferred collector buffer is ready */
    if (listener->lastbuf &&
        FD_ISSET(fbCollectorGetFD(fBufGetCollector(listener->lastbuf)),
                                  &lfdset.fds)) {
        return listener->lastbuf;
    }

    /* return first available collector buffer */
    lfdset.fbuf = NULL;
    g_hash_table_foreach(listener->fdtab,
                         (GHFunc)fbListenerWaitSearch, &lfdset);
    listener->lastbuf = lfdset.fbuf;
    return lfdset.fbuf;
}

fBuf_t *fbListenerWaitNoCollectors(
    fbListener_t                *listener,
    GError                      **err)
{
    fbListenerWaitFDSet_t       lfdset;
    uint8_t                     byte;
    int                         rc;

    /* set up the select call... */
    FD_ZERO(&lfdset.fds);
    lfdset.maxfd = 0;
    /* interrupt pipe read end */
    fbListenerWaitAddFD(GINT_TO_POINTER(listener->rip), NULL, &lfdset);
    /* listener socket if available */
    if (listener->lsock >= 0) {
        fbListenerWaitAddFD(GINT_TO_POINTER(listener->lsock), NULL, &lfdset);
    }

    /* wait for data available on one of our file descriptors */
    rc = select(lfdset.maxfd + 1, &lfdset.fds, NULL, NULL, NULL);
    if (rc < 0) {
        if (errno == EINTR) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "Interrupted listener wait");
            return NULL;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "listener wait error: %s",
                        strerror(errno));
            return NULL;
        }
    }

    /* handle interrupt pipe read end */
    if (FD_ISSET(listener->rip, &lfdset.fds)) {
        /* consume and ignore return */
        read(listener->rip, &byte, sizeof(byte));
        /* throw error */
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                    "External interrupt on pipe");
        return NULL;
    }

    /* handle any pending accept, return the accepted buffer immediately. */
    if (listener->lsock >= 0 &&
        FD_ISSET(listener->lsock, &lfdset.fds)) {
        lfdset.fbuf = fbListenerWaitAccept(listener, err);
        if (!lfdset.fbuf) return NULL;
        listener->lastbuf = lfdset.fbuf;
        return lfdset.fbuf;
    }
    /* this should never happen */
    return NULL;
}


static void   fbListenerInterruptCollectors(
    void                        *vfd __attribute__((unused)),
    void                        *fbuf,
    fbListenerWaitFDSet_t       *lfdset __attribute__((unused)))
{
    fBufInterruptSocket(fbuf);
}


/**
 * fbListenerInterrupt
 *
 *
 *
 *
 */
void fbListenerInterrupt(
    fbListener_t        *listener)
{
    uint8_t             byte = 0xe7;

    /* send interrrupts to the collectors, then to the listener */
    g_hash_table_foreach(listener->fdtab,
                         (GHFunc)fbListenerInterruptCollectors,
                         NULL);

    /* write and ignore return */
    write(listener->wip, &byte, sizeof(byte));
    write(listener->rip, &byte, sizeof(byte));

}

/**
 * fbListenerGetConnSpec
 *
 *
 *
 *
 */
fbConnSpec_t        *fbListenerGetConnSpec(
    fbListener_t        *listener)
{
    return listener->spec;
}


/**
 *fbListenerGetCollector
 *
 * gets the collector allocated to the listener
 *
 */
gboolean            fbListenerGetCollector(
    fbListener_t        *listener,
    fbCollector_t       **collector,
    GError              **err)
{
    if (NULL == listener->collectorHandle) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "no collector available to be retrieved");
        return FALSE;
    }

    *collector = listener->collectorHandle;

    return TRUE;
}

/* returns NULL or pointer to allocated group structure */

fbListenerGroup_t* fbListenerGroupAlloc(
    void)
{
    fbListenerGroup_t   *group = NULL;
    group = g_slice_new0( fbListenerGroup_t );
    if (!group) {
        return NULL;
    }
    group->head = NULL;
    group->tableForDescriptorsToListeners = NULL;

    return group;
}

/* returns 0 upon success.  "1" if entry couldn't get created
                    maybe "2" if either of the incoming pointers is NULL */
int fbListenerGroupAddListener(
    fbListenerGroup_t  *group,
    const fbListener_t *listener)
{
    fbListenerEntry_t   *entry = NULL;

    if (!group || !listener) {
        return 2;
    }

    entry = g_slice_new0( fbListenerEntry_t );

    if (!entry) {
        /* needs to be something like ERR_NO_MEM */
        return 1;
    }

    entry->prev = NULL;
    entry->next = group->head;
    entry->listener = (fbListener_t*)listener;

    if (group->head) {
        group->head->prev = entry;
    }

    group->head = entry;

    return 0;
}

/* returns 0 on success.  "1" if not found. "2" if a pointer is NULL */
int fbListenerGroupDeleteListener(
    fbListenerGroup_t   *group,
    const fbListener_t  *listener)
{
    fbListenerEntry_t   *entry = NULL;

    if (!group || !listener) {
        return 2;
    }

    for(entry = group->head; entry; entry = entry->next) {
        if (entry->listener == listener) {
            if (entry->prev) {
                entry->prev->next = entry->next;
            }

            if (entry->next) {
                entry->next->prev = entry->prev;
            }

            g_free(entry);

            return 0;
        }
    }

    return 1;
}

fbListenerGroupResult_t* fbListenerGroupWait(
    fbListenerGroup_t   *group,
    GError             **err)
{
    fbListenerWaitFDSet_t       lfdset;
    uint8_t                     byte;
    int                         rc;
    fbListenerEntry_t          *entry       = NULL;
    fbListenerGroupResult_t    *resultHead  = NULL;
    fbListenerGroupResult_t    *result      = NULL;

    g_assert(group);

    /* set up the select call... */
    FD_ZERO(&lfdset.fds);
    lfdset.maxfd = 0;
    /* interrupt pipe read end */
    for(entry = group->head; entry; entry = entry->next) {
        fbListenerWaitAddFD(GINT_TO_POINTER(entry->listener->rip),
                            NULL,
                            &lfdset);
        /* listener socket if available */
        if (entry->listener->lsock >= 0) {
            fbListenerWaitAddFD(GINT_TO_POINTER(entry->listener->lsock),
                                NULL,
                                &lfdset);
        }
        /* any open collectors we may have */
        g_hash_table_foreach(entry->listener->fdtab,
                            (GHFunc)fbListenerWaitAddFD, &lfdset);
    }

    /* wait for data available on one of our file descriptors */
    rc = select(lfdset.maxfd + 1, &lfdset.fds, NULL, NULL, NULL);
    if (rc < 0) {
        if (errno == EINTR) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "Interrupted listener wait");
            return NULL;
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "listener wait error: %s",
                        strerror(errno));
            return NULL;
        }
    }

    for(entry = group->head; entry; entry = entry->next) {
        /* handle interrupt pipe read end */
        if (FD_ISSET(entry->listener->rip, &lfdset.fds)) {
            /* consume and ignore return */
            read(entry->listener->rip, &byte, sizeof(byte));
            /* throw error */
            /* maybe */
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "External interrupt on pipe");
            continue;
        }

        /* handle any pending accept, return the accepted buffer immediately. */
        if (entry->listener->lsock >= 0 &&
            FD_ISSET(entry->listener->lsock, &lfdset.fds))
        {
            result              = g_slice_new0( fbListenerGroupResult_t );
            result->fbuf        = fbListenerWaitAccept(entry->listener, err);
            result->listener    = entry->listener;
            if (!result->fbuf) {
                /* what to do here */
                g_free(result);
                continue;
            }
            entry->listener->lastbuf = result->fbuf;
            result->next = resultHead;
            resultHead = result;
        }

        if (entry->listener->lastbuf &&
            FD_ISSET(fbCollectorGetFD(
                        fBufGetCollector(entry->listener->lastbuf)),
                                      &lfdset.fds)) {
            result              = g_slice_new0( fbListenerGroupResult_t );
            result->fbuf        = entry->listener->lastbuf;
            result->listener    = entry->listener;
            entry->listener->lastbuf = result->fbuf;
            result->next = resultHead;
            resultHead = result;

            return resultHead;
        }

        lfdset.fbuf = NULL;
        g_hash_table_foreach(entry->listener->fdtab,
                             (GHFunc)fbListenerWaitSearch, &lfdset);
        entry->listener->lastbuf = lfdset.fbuf;
    }

    return resultHead;
}

/* Loops until and error, a callback returns false, or an interrupts
 */
gboolean fbListenerWaitAcceptCallback(
    fbListener_t                *listener,
    fbAcceptCallback_fn         callback,
    GError                      **err)
{
    fbListenerWaitFDSet_t       lfdset;
    uint8_t                     byte;
    int                         rc;
    gboolean                    callbackResult = TRUE;
    /* set up the select call... */

    while(callbackResult) {
        FD_ZERO(&lfdset.fds);
        lfdset.maxfd = 0;
        /* interrupt pipe read end */
        fbListenerWaitAddFD(GINT_TO_POINTER(listener->rip), NULL, &lfdset);
        /* listener socket if available */
        if (listener->lsock >= 0) {
            fbListenerWaitAddFD(GINT_TO_POINTER(listener->lsock), NULL, &lfdset);
        }

        /* wait for data available on one of our file descriptors */
        rc = select(lfdset.maxfd + 1, &lfdset.fds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                            "Interrupted listener wait");
                return FALSE;
            } else {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                            "listener wait error: %s",
                            strerror(errno));
                return FALSE;
            }
        }

        /* handle interrupt pipe read end */
        if (FD_ISSET(listener->rip, &lfdset.fds)) {
            /* consume and ignore return */
            read(listener->rip, &byte, sizeof(byte));
            /* throw error */
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                        "External interrupt on pipe");
            return FALSE;
        }

        /* handle any pending accept, return the accepted buffer immediately. */
        if (listener->lsock >= 0 &&
            FD_ISSET(listener->lsock, &lfdset.fds))
        {
            lfdset.fbuf = fbListenerWaitAccept(listener, err);
            if (!lfdset.fbuf) {
                return FALSE;
            }
            listener->lastbuf = lfdset.fbuf;
            callbackResult = (callback)(lfdset.fbuf, listener,
                                        fbCollectorGetPeer(listener->collectorHandle), err);
        }
    }
    return FALSE;
}


/* Loops forever until an error occurs, a callback returns error, or the
   listener was interrupted.  If it returns TRUE, there's a bug */

gboolean fbListenerGroupWaitAcceptCallback(
    fbListenerGroup_t   *group,
    fbAcceptCallback_fn  callback,
    GError             **err)
{
    fbListenerWaitFDSet_t       lfdset;
    uint8_t                     byte;
    int                         rc;
    fbListenerEntry_t          *entry       = NULL;
    gboolean                    callbackResults = TRUE;

    g_assert(group);

    while (callbackResults) {
        /* set up the select call... */
        FD_ZERO(&lfdset.fds);
        lfdset.maxfd = 0;
        /* interrupt pipe read end */
        for(entry = group->head; entry; entry = entry->next) {
            fbListenerWaitAddFD(GINT_TO_POINTER(entry->listener->rip),
                                NULL,
                                &lfdset);
            /* listener socket if available */
            if (entry->listener->lsock >= 0) {
                fbListenerWaitAddFD(GINT_TO_POINTER(entry->listener->lsock),
                                    NULL,
                                    &lfdset);
            }
        }

        /* wait for data available on one of our file descriptors */
        rc = select(lfdset.maxfd + 1, &lfdset.fds, NULL, NULL, NULL);
        if (rc < 0) {
            if (errno == EINTR) {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                            "Interrupted listener wait");
                return FALSE;
            } else {
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                            "listener wait error: %s",
                            strerror(errno));
                return FALSE;
            }
        }

        for(entry = group->head; entry; entry = entry->next) {
            /* handle interrupt pipe read end */
            if (FD_ISSET(entry->listener->rip, &lfdset.fds)) {
                /* consume and ignore return */
                read(entry->listener->rip, &byte, sizeof(byte));
                /* throw error */
                callbackResults = FALSE;
                g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLREAD,
                            "External interrupt on pipe");
                continue;
            }

            /* handle any pending accept, return the accepted buffer immediately. */
            if (entry->listener->lsock >= 0 &&
                FD_ISSET(entry->listener->lsock, &lfdset.fds))
            {
                lfdset.fbuf = fbListenerWaitAccept(entry->listener, err);
                if (!(lfdset.fbuf)) {
                    callbackResults = FALSE;
                    continue;
                }
                entry->listener->lastbuf = lfdset.fbuf;
                callbackResults &= (callback)(lfdset.fbuf, entry->listener,
                                              fbCollectorGetPeer(entry->listener->collectorHandle), err);
            }
        }
    }
    return callbackResults;
}

/*  Given a socket descriptor with an existing connection, return an fbuf
 *  fBufNext can be called on it
 *  Interrupting the accepting of new connections on this socket is the
 *  responsibility of the caller, it cannot be done with
 *  fbListenerInterrupt().  However, the collectors attached to this listener
 *  can be interrupted by this call, which short circuits fBufNext().
 *  Call fbListenerInterrupt to stop the collectors, then stop the listener
 *  socket on your own.
 */
fBuf_t  *fbListenerOwnSocketCollectorTCP(
    fbListener_t   *listener,
    int             sock,
    GError        **err)
{
    fbCollector_t   *collector  = NULL;
    fBuf_t          *fbuf       = NULL;
    fbConnSpec_t     connSpec;
    g_assert(listener);

    if (sock <= 2) {
        /* invalid socket */
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
            "Invalid socket descriptor");
        return NULL;
    }

    connSpec.transport = FB_TCP;
    listener->spec = &connSpec;

    collector = fbCollectorAllocSocket(listener, NULL, sock, NULL, 0);

    fbuf = fBufAllocForCollection(fbSessionClone(listener->session), collector);

    fBufSetAutomaticMode(fbuf, FALSE);

    /* Add buffer to the file descriptor table */
    g_hash_table_insert(listener->fdtab, GINT_TO_POINTER(sock), fbuf);

    /* store the collector handle */
    listener->collectorHandle = collector;

    listener->spec = NULL;

    /* All done. */
    return fbuf;
}

/* not even remotely tested yet */
fBuf_t  *fbListenerOwnSocketCollectorTLS(
    fbListener_t   *listener,
    int             sock,
    GError        **err)
{
    fbCollector_t   *collector  = NULL;
    fBuf_t          *fbuf       = NULL;
    g_assert(listener);

    if (sock <= 2) {
        /* invalid socket */
        return NULL;
    }

    listener->spec->transport = FB_TLS_TCP;

/*    collector = fbCollectorAllocTLS(listener, NULL, sock, NULL, 0, err);*/

    fbuf = fBufAllocForCollection(fbSessionClone(listener->session), collector);

    fBufSetAutomaticMode(fbuf, FALSE);

    /* Add buffer to the file descriptor table */
    g_hash_table_insert(listener->fdtab, GINT_TO_POINTER(sock), fbuf);

    /* store the collector handle */
    listener->collectorHandle = collector;

    (void)err;

    /* All done. */
    return fbuf;
}

void fbListenerRemoveLastBuf(
    fBuf_t         *fbuf,
    fbListener_t   *listener)
{
    if (listener->lastbuf == fbuf) {
        listener->lastbuf = NULL;
    }
}

gboolean fbListenerCallAppInit(
    fbListener_t       *listener,
    fbUDPConnSpec_t    *spec,
    GError             **err)
{

    if (listener->appinit) {
        if (!listener->appinit(listener, &(spec->ctx), listener->lsock,
                               &(spec->peer.so), spec->peerlen, err)) {
            return FALSE;
        }
    }

    return TRUE;

}

fbSession_t *fbListenerSetPeerSession(
    fbListener_t        *listener,
    fbSession_t         *session)
{

    fbSession_t *new_session = session;

    if (!new_session) {
        new_session = fbSessionClone(listener->session);
    }

    listener->session = new_session;

    fBufSetSession(listener->lastbuf, new_session);

    fbSessionSetTemplateBuffer(new_session, listener->lastbuf);

    return new_session;

}
