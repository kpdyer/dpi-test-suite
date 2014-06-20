/**
 * @internal
 *
 * @file fbexporter.c
 *
 * IPFIX Exporting Process single transport session implementation
 *
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
 *
 */

#define _FIXBUF_SOURCE_
/*#define _GNU_SOURCE*/
#include <fixbuf/private.h>

#ident "$Id: fbexporter.c 18744 2013-03-07 17:48:39Z ecoff_svn $"

/**
 * If set in exporter SCTP mode, use simple automatic stream selection as
 * specified in the IPFIX protocol without flexible stream selection: send
 * templates on stream 0, and data on stream 1.
 */
#define FB_F_SCTP_AUTOSTREAM        0x80000000

/**
 * If set in exporter SCTP mode, use TTL-based partial reliability for
 * non-template messages.
 */
#define FB_F_SCTP_PR_TTL            0x40000000

typedef gboolean    (*fbExporterOpen_fn)(
    fbExporter_t                *exporter,
    GError                      **err);

typedef gboolean    (*fbExporterWrite_fn) (
    fbExporter_t                *exporter,
    uint8_t                     *msgbase,
    size_t                      msglen,
    GError                      **err);

typedef void        (*fbExporterClose_fn)(
    fbExporter_t                *exporter);

struct fbExporter_st {
    /** Specifier used for stream open */
    union {
        fbConnSpec_t            *conn;
        #ifdef HAVE_SPREAD
        fbSpreadSpec_t          *spread;
        #endif
        char                    *path;
    }                           spec;
    /** Current export stream */
    union {
        /** Buffered file pointer, for file transport */
        FILE                    *fp;
        /**
         * Unbuffered socket, for SCTP, TCP, or UDP transport.
         * Also used as base socket for TLS and DTLS support.
         */
        int                     fd;
    }                           stream;
    /** SCTP mode. Union of FB_SCTP_F_* flags. */
    uint32_t                    sctp_mode;
    /** Next SCTP stream */
    int                         sctp_stream;
    /** Partial reliability parameter (see mode) */
    int                         sctp_pr_param;
#if HAVE_OPENSSL
    /** OpenSSL socket, for TLS or DTLS over the socket in fd. */
    SSL                         *ssl;
#endif
    gboolean                    active;
    fbExporterOpen_fn           exopen;
    fbExporterWrite_fn          exwrite;
    fbExporterClose_fn          exclose;
    uint16_t                    mtu;
};

/**
 *fbExporterOpenFile
 *
 *
 * @param exporter
 * @param err
 *
 * @return
 */
static gboolean fbExporterOpenFile (
    fbExporter_t                *exporter,
    GError                      **err)
{
    /* check to see if we're opening stdout */
    if ((strlen(exporter->spec.path) == 1) &&
        (exporter->spec.path[0] == '-'))
    {
        /* don't open a terminal */
        if (isatty(fileno(stdout))) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "Refusing to open stdout terminal for export");
            return FALSE;
        }

        /* yep, stdout */
        exporter->stream.fp = stdout;
    } else {
        /* nope, just a regular file */
        exporter->stream.fp = fopen(exporter->spec.path, "w");
    }

    /* check for error */
    if (!exporter->stream.fp) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "Couldn't open %s for export: %s",
                    exporter->spec.path, strerror(errno));
        return FALSE;
    }

    /* set active flag */
    exporter->active = TRUE;

    return TRUE;
}

/**
 *fbExporterWriteFile
 *
 *
 * @param exporter
 * @param msgbase
 * @param msglen
 * @param err
 *
 * @return
 */
static gboolean fbExporterWriteFile(
    fbExporter_t                *exporter,
    uint8_t                     *msgbase,
    size_t                      msglen,
    GError                      **err)
{
    size_t                      rc;

    rc = fwrite(msgbase, 1, msglen, exporter->stream.fp);

    if (rc == msglen) {
        return TRUE;
    } else {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "Couldn't write %u bytes to %s: %s",
                    (uint32_t)msglen, exporter->spec.path, strerror(errno));
        return FALSE;
    }
}

/**
 *fbExporterCloseFile
 *
 *
 * @param exporter
 *
 */
static void fbExporterCloseFile (
    fbExporter_t                *exporter)
{
    if (exporter->stream.fp == stdout) {
        fflush(exporter->stream.fp);
    } else {
        fclose(exporter->stream.fp);
    }
    exporter->stream.fp = NULL;
    exporter->active = FALSE;
}

/**
 *fbExporterAllocFile
 *
 *
 * @param path
 * @param exporter
 *
 * @return
 */
fbExporter_t    *fbExporterAllocFile(
    const char      *path)
{
    fbExporter_t    *exporter;

    /* Create a new exporter */
    exporter = g_slice_new0(fbExporter_t);

    /* Copy the path */
    exporter->spec.path = g_strdup(path);

    /* Set up stream management functions */
    exporter->exopen = fbExporterOpenFile;
    exporter->exwrite = fbExporterWriteFile;
    exporter->exclose = fbExporterCloseFile;
    exporter->mtu = 65496;

    return exporter;
}

/**
 *fbExporterSetFilePath
 *
 *
 * @param exporter
 * @param path
 *
 */
void         fbExporterSetFilePath(
    fbExporter_t    *exporter,
    char            *path)
{
    /* Only valid if this is a file path based exporter */
    g_assert(exporter->exopen == fbExporterOpenFile);

    /* Force exporter closed if it's active */
    if (exporter->active) exporter->exclose(exporter);

    /* Free old file path if necessary */
    if (exporter->spec.path) {
        g_free(exporter->spec.path);
    }

    exporter->spec.path = g_strdup(path);
}

/**
 *fbExporterAllocFP
 *
 * @param fp
 *
 * @return
 */
fbExporter_t    *fbExporterAllocFP(
    FILE            *fp)
{
    fbExporter_t    *exporter;

    /* Create a new exporter */
    exporter = g_slice_new0(fbExporter_t);

    /* Reference the path */
    exporter->spec.path = g_strdup("FP");

    /* Set up stream management functions */
    exporter->exwrite = fbExporterWriteFile;
    exporter->mtu = 65496;

    /* set active flag */
    exporter->active = TRUE;

    /* set file pointer */
    exporter->stream.fp = fp;

    return exporter;
}

/**
 *fbExporterSetFP
 *
 *
 * @param exporter
 * @param fp
 *
 */
void         fbExporterSetFP(
    fbExporter_t    *exporter,
    FILE            *fp)
{
    /* Only valid if this is a file path based exporter */
    g_assert(!exporter->exopen);
    g_assert(exporter->exwrite == fbExporterWriteFile);

    /* Change file pointer */
    exporter->stream.fp = fp;
}

/**
 *fbExporterIgnoreSigpipe
 *
 *
 */
static void fbExporterIgnoreSigpipe()
{
    static gboolean ignored = FALSE;
    struct sigaction sa, osa;

    if (ignored) return;

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGPIPE,&sa,&osa)) {
        g_error("sigaction(SIGPIPE) failed: %s", strerror(errno));
    }

    ignored = TRUE;
}

/**
 *fbExporterMaxSendbuf
 *
 *
 * @param sock
 * @param size
 *
 * @return
 */
static gboolean fbExporterMaxSendbuf(
    int         sock,
    int         *size)
{
    while (*size > 4096) {
        if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, size,
                       sizeof(*size)) == 0)
        {
            return TRUE;
        }
        if (errno != ENOBUFS) {
            return FALSE;
        }
        *size -= (*size > 1024 * 1024)
                        ? 1024 * 1024
                        : 2048;
    }
    return FALSE;
}

#define FB_SOCKBUF_DEFAULT (4 * 1024 * 1024)

/**
 *fbExporterOpenSocket
 *
 * @param exporter
 * @param err
 *
 * @return
 */
static gboolean fbExporterOpenSocket(
    fbExporter_t                *exporter,
    GError                      **err)
{
    struct addrinfo             *ai = NULL;
    int                         sockbuf_sz = FB_SOCKBUF_DEFAULT;

    /* Turn the exporter connection specifier into an addrinfo */
    if (!fbConnSpecLookupAI(exporter->spec.conn, FALSE, err)) return FALSE;
    ai = (struct addrinfo *)exporter->spec.conn->vai;

    /* ignore sigpipe if we're doing TCP or SCTP export */
    if ((exporter->spec.conn->transport == FB_TCP) ||
        (exporter->spec.conn->transport == FB_TLS_TCP)
#if FB_ENABLE_SCTP
        || (exporter->spec.conn->transport == FB_SCTP)
        || (exporter->spec.conn->transport == FB_DTLS_SCTP)
#endif
    ) {
        fbExporterIgnoreSigpipe();
    }

    /* open socket of appropriate type for connection specifier */
    do {
#if FB_ENABLE_SCTP
        if ((exporter->spec.conn->transport == FB_SCTP) ||
            (exporter->spec.conn->transport == FB_DTLS_SCTP))
        {
                /* Kludge for SCTP. addrinfo doesn't accept SCTP hints. */
                ai->ai_socktype = SOCK_STREAM;
                ai->ai_protocol = IPPROTO_SCTP;
        }
#endif

        exporter->stream.fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (exporter->stream.fd < 0) continue;
        if (connect(exporter->stream.fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(exporter->stream.fd);
    } while ((ai = ai->ai_next));

    /* check for no openable socket */
    if (ai == NULL) {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't create connected TCP socket to %s:%s %s",
                    exporter->spec.conn->host, exporter->spec.conn->svc,
                    strerror(errno));
        return FALSE;
    }

    /* increase send buffer size for UDP */
    if ((exporter->spec.conn->transport == FB_UDP) ||
        (exporter->spec.conn->transport == FB_DTLS_UDP))
    {
        if (!fbExporterMaxSendbuf(exporter->stream.fd, &sockbuf_sz)) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                        "couldn't set socket buffer size on %s: %s",
                        exporter->spec.conn->host, strerror(errno));
            close(exporter->stream.fd);
            return FALSE;
        }
    }

    /* set active flag */
    exporter->active = TRUE;

    return TRUE;
}

#if FB_ENABLE_SCTP

/**
 *fbExporterWriteSCTP
 *
 *
 * @param exporter
 * @param msgbase
 * @param msglen
 * @param err
 *
 * @return
 */
static gboolean fbExporterWriteSCTP (
    fbExporter_t                *exporter,
    uint8_t                     *msgbase,
    size_t                      msglen,
    GError                      **err)
{
    ssize_t                     rc;
    uint16_t                    initial_setid;
    gboolean                    is_template;
    int                         sctp_flags = 0;
    uint32_t                    sctp_ttl = 0;

    /* Check to see if this is a template message */
    initial_setid = *(uint16_t *)(msgbase + 16);
    if (initial_setid == FB_TID_TS || initial_setid == FB_TID_OTS) {
        is_template = TRUE;
    } else {
        is_template = FALSE;
    }

    /* Do automatic stream selection if requested. */
    if (exporter->sctp_mode & FB_F_SCTP_AUTOSTREAM) {
        if (is_template) {
            exporter->sctp_stream = 0;
        } else {
            exporter->sctp_stream = 1;
        }
    }

    /* Use partial reliability if requested for non-template messages */
    if (!is_template && (exporter->sctp_mode & FB_F_SCTP_PR_TTL)) {
        sctp_flags |= FB_F_SCTP_PR_TTL;
        sctp_ttl = exporter->sctp_pr_param;
    }

    rc = sctp_sendmsg(exporter->stream.fd, msgbase, msglen,
                      NULL, 0,      /* destination sockaddr */
                      0,            /* payload protocol */
                      sctp_flags,   /* flags */
                      exporter->sctp_stream,  /* stream */
                      sctp_ttl,     /* message lifetime (ms) */
                      0);           /* context */

    if (rc == (ssize_t)msglen) {
        return TRUE;
    } else if (rc == -1) {
        if (errno == EPIPE) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLWRITE,
                        "Connection reset (EPIPE) on SCTP write");
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "I/O error: %s", strerror(errno));
        }
        return FALSE;
    } else {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "short write: wrote %d while writing %lu",
                    (int)rc, msglen);
        return FALSE;
    }
}

#endif /* FB_ENABLE_SCTP */


/**
 *fbExporterWriteTCP
 *
 *
 * @param exporter
 * @param msgbase
 * @param msglen
 * @param err
 *
 * @return
 */
static gboolean fbExporterWriteTCP (
    fbExporter_t                *exporter,
    uint8_t                     *msgbase,
    size_t                      msglen,
    GError                      **err)
{
    ssize_t                     rc;

    rc = write(exporter->stream.fd, msgbase, msglen);
    if (rc == (ssize_t)msglen) {
        return TRUE;
    } else if (rc == -1) {
        if (errno == EPIPE) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_NLWRITE,
                        "Connection reset (EPIPE) on TCP write");
        } else {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "I/O error: %s", strerror(errno));
        }
        return FALSE;
    } else {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "short write: wrote %d while writing %u",
                    (int)rc, (uint32_t)msglen);
        return FALSE;
    }
}

/**
 * fbExporterWriteUDP
 *
 *
 * @param exporter
 * @param msgbase
 * @param msglen
 * @param err
 *
 * @return
 */
static gboolean fbExporterWriteUDP (
    fbExporter_t                *exporter,
    uint8_t                     *msgbase,
    size_t                      msglen,
    GError                      **err)
{
    static gboolean             sendGood = TRUE;
    ssize_t                     rc;

    /* Send the buffer as a single message */
    rc = send(exporter->stream.fd, msgbase, msglen, 0);

    /* Deal with the results */
    if (rc == (ssize_t)msglen) {
        return TRUE;
    } else if (rc == -1) {
        if (TRUE == sendGood) {
            g_warning( "I/O error on UDP send: %s (socket closed on receiver?)",
                strerror(errno));
            g_warning("packets will be lost");
            send(exporter->stream.fd, msgbase, msglen, 0);
            sendGood = FALSE;
            return TRUE;
        }
        return TRUE;
    } else {
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                    "Short write on UDP send: wrote %d while writing %u",
                    (int)rc, (uint32_t)msglen);
        return FALSE;
    }
}

/**
 *fbExporterCloseSocket
 *
 *
 * @param exporter
 *
 */
static void fbExporterCloseSocket (
    fbExporter_t                *exporter)
{
    close(exporter->stream.fd);
    exporter->active = FALSE;
}

#if HAVE_OPENSSL

/**
 *fbExporterOpenTLS
 *
 *
 * @param exporter
 * @param err
 *
 * @return
 */
static gboolean fbExporterOpenTLS (
    fbExporter_t                *exporter,
    GError                      **err)
{
    BIO                         *conn = NULL;
    gboolean                    ok = TRUE;

    /* Initialize SSL context if necessary */
    if (!exporter->spec.conn->vssl_ctx) {
        if (!fbConnSpecInitTLS(exporter->spec.conn, FALSE, err)) {
            return FALSE;
        }
    }

    /* open underlying socket */
    if (!fbExporterOpenSocket(exporter, err)) return FALSE;

    /* wrap a stream BIO around the opened socket */
    if (!(conn = BIO_new_socket(exporter->stream.fd, 1))) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't wrap socket to %s:%s for TLS: %s",
                    exporter->spec.conn->host, exporter->spec.conn->svc,
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* create SSL socket */
    if (!(exporter->ssl = SSL_new((SSL_CTX *)exporter->spec.conn->vssl_ctx))) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldnt create TLS socket: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* connect to it */
    SSL_set_bio(exporter->ssl, conn, conn);
    if (SSL_connect(exporter->ssl) <= 0) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't connect TLS socket to %s:%s: %s",
                    exporter->spec.conn->host, exporter->spec.conn->svc,
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* FIXME do post-connection verification */

end:
    if (!ok) {
        exporter->active = FALSE;
        if (exporter->ssl) {
            SSL_free(exporter->ssl);
            exporter->ssl = NULL;
        } else if (conn) {
            BIO_vfree(conn);
        }
    }
    return ok;
}

#if HAVE_OPENSSL_DTLS

/**
 *fbExporterOpenDTLS
 *
 * @param exporter
 * @param err
 *
 * @return
 *
 */
static gboolean fbExporterOpenDTLS (
    fbExporter_t                *exporter,
    GError                      **err)
{
    BIO                         *conn = NULL;
    gboolean                    ok = TRUE;
    struct sockaddr             peer;
    size_t                      peerlen = sizeof(struct sockaddr);

    /* Initialize SSL context if necessary */
    if (!exporter->spec.conn->vssl_ctx) {
        if (!fbConnSpecInitTLS(exporter->spec.conn, FALSE, err)) {
            return FALSE;
        }
    }

    /* open underlying socket */
    if (!fbExporterOpenSocket(exporter, err)) return FALSE;

    /* wrap a datagram BIO around the opened socket */
    if (!(conn = BIO_new_dgram(exporter->stream.fd, 1))) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't wrap socket to %s:%s for DTLS: %s",
                    exporter->spec.conn->host, exporter->spec.conn->svc,
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* Tell dgram bio what its name is */
        if (getsockname (exporter->stream.fd, &peer, (socklen_t *)&peerlen) < 0) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldn't wrap socket to %s:%s for DTLS: %s",
                    exporter->spec.conn->host, exporter->spec.conn->svc,
                    strerror(errno));
        goto end;
    }
    BIO_ctrl_set_connected(conn, 1, &peer);

    /* create SSL socket */
    if (!(exporter->ssl = SSL_new((SSL_CTX *)exporter->spec.conn->vssl_ctx))) {
        ok = FALSE;
        g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                    "couldnt create DTLS socket: %s",
                    ERR_error_string(ERR_get_error(), NULL));
        while (ERR_get_error());
        goto end;
    }

    /* connect to it */
    SSL_set_bio(exporter->ssl, conn, conn);
        SSL_set_connect_state(exporter->ssl);

    /* FIXME do post-connection verification */

end:
    if (!ok) {
        exporter->active = FALSE;
        if (exporter->ssl) {
            SSL_free(exporter->ssl);
            exporter->ssl = NULL;
        } else if (conn) {
            BIO_vfree(conn);
        }
    }
    return ok;
}

#endif /* HAVE_OPENSSL_DTLS */

/**
 *fbExporterWriteTLS
 *
 *
 * @param exporter
 * @param msgbase
 * @param msglen
 * @param err
 *
 * @return
 */
static gboolean fbExporterWriteTLS (
    fbExporter_t                *exporter,
    uint8_t                     *msgbase,
    size_t                      msglen,
    GError                      **err)
{
    int                         rc;

    while (msglen) {
        rc = SSL_write(exporter->ssl, msgbase, msglen);
        if (rc <= 0) {
            g_set_error(err, FB_ERROR_DOMAIN, FB_ERROR_IO,
                        "I/O error: %s",
                        ERR_error_string(ERR_get_error(), NULL));
            while (ERR_get_error());
            return FALSE;
        }

        /* we sent some bytes - advance pointers */
        msglen -= rc;
        msgbase += rc;
    }

    return TRUE;
}

/**
 *fbExporterCloseTLS
 *
 *
 * @param exporter
 *
 */
static void fbExporterCloseTLS (
    fbExporter_t                *exporter)
{
    SSL_shutdown(exporter->ssl);
    SSL_free(exporter->ssl);
    exporter->active = FALSE;
}

#endif /* HAVE_OPENSSL */

/**
 *fbExporterGetMTU
 *
 * @param exporter
 *
 * @return
 */
uint16_t        fbExporterGetMTU(
    fbExporter_t                *exporter)
{
    return exporter->mtu;
}

/**
 *fbExporterAllocNet
 *
 * @param spec
 *
 * @return
 */
fbExporter_t    *fbExporterAllocNet(
    fbConnSpec_t    *spec)
{
    fbExporter_t    *exporter = NULL;

    /* Host must not be null */
    g_assert(spec->host);

    /* Create a new exporter */
    exporter = g_slice_new0(fbExporter_t);

    /* Copy the connection specifier */
    exporter->spec.conn = fbConnSpecCopy(spec);

    /* Set up functions */
    switch (spec->transport) {
#if FB_ENABLE_SCTP
    case FB_SCTP:
        exporter->exopen = fbExporterOpenSocket;
        exporter->exwrite = fbExporterWriteSCTP;
        exporter->exclose = fbExporterCloseSocket;
        exporter->sctp_mode = FB_F_SCTP_AUTOSTREAM;
        exporter->sctp_stream = 0;
        exporter->mtu = 8192;
        break;
#endif
    case FB_TCP:
        exporter->exopen = fbExporterOpenSocket;
        exporter->exwrite = fbExporterWriteTCP;
        exporter->exclose = fbExporterCloseSocket;
        exporter->mtu = 8192;
        break;
    case FB_UDP:
        exporter->exopen = fbExporterOpenSocket;
        exporter->exwrite = fbExporterWriteUDP;
        exporter->exclose = fbExporterCloseSocket;
        exporter->mtu = 1420;
        break;
#if HAVE_OPENSSL
#if HAVE_OPENSSL_DTLS_SCTP
    case FB_DTLS_SCTP:
        exporter->exopen = fbExporterOpenDTLS;
        exporter->exwrite = fbExporterWriteTLS;
        exporter->exclose = fbExporterCloseTLS;
        exporter->sctp_mode = FB_F_SCTP_AUTOSTREAM;
        exporter->sctp_stream = 0;
        exporter->mtu = 8192;
        break;
#endif
    case FB_TLS_TCP:
        exporter->exopen = fbExporterOpenTLS;
        exporter->exwrite = fbExporterWriteTLS;
        exporter->exclose = fbExporterCloseTLS;
        exporter->mtu = 8192;
        break;
#if HAVE_OPENSSL_DTLS
    case FB_DTLS_UDP:
        exporter->exopen = fbExporterOpenDTLS;
        exporter->exwrite = fbExporterWriteTLS;
        exporter->exclose = fbExporterCloseTLS;
        exporter->mtu = 1320;
        break;
#endif
#endif
    default:
#ifndef FB_ENABLE_SCTP
        if (spec->transport == FB_SCTP || spec->transport == FB_DTLS_SCTP) {
            g_error("Libfixbuf not enabled for SCTP Transport. "
                    " Run configure with --with-sctp");
        }
#endif
        if (spec->transport == FB_TLS_TCP || spec->transport == FB_DTLS_SCTP ||
            spec->transport == FB_DTLS_UDP) {
            g_error("Libfixbuf not enabled for this mode of transport. "
                    " Run configure with --with-openssl");
        }
    }

    /* Return new exporter */
    return exporter;
}

#if HAVE_SPREAD

/**
 * fbExporterSpreadReceiver
 *
 */

static void * fbExporterSpreadReceiver(
    void *arg )
{
    int             i = 0;
    char            grp[MAX_GROUP_NAME];
    fbExporter_t    *exporter = (fbExporter_t *)arg;
    fbSpreadSpec_t  *spread = exporter->spec.spread;
    service         service_type = 0;
    char            sender[MAX_GROUP_NAME];
    int             num_groups = 0;
    int16           mess_type = 0;
    int             endian_mismatch;
    int             run = 1;
    int             ret;
    membership_info memb_info;

    #if 0
    /*  this loop is to allow a debugger to be attached */
    int foo = 1;
    do {
        sleep( 1 );
    } while (foo);
    #endif

    ret = SP_connect( spread->daemon, 0, 0, 1,
                      &(spread->recv_mbox), spread->recv_privgroup );

    if (ret != ACCEPT_SESSION) {

        g_set_error( &(spread->recv_err), FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "error connecting to Spread daemon %s: %s",
                     spread->daemon, fbConnSpreadError( ret ) );
        return 0;
    }

    for (i = 0; i < spread->num_groups; i++) {
         /* exporter listener only joins template/control plane group,
         the group name is always the name of the data plane group
         plus 'T' added to the end. */
        memset( grp, 0, sizeof( grp ) );
        strncpy( grp, spread->groups[i].name, sizeof( grp) - 2 );
        strcat( grp, "T" );
        ret = SP_join( spread->recv_mbox, grp );
        if (ret) {
            g_set_error( &(spread->recv_err), FB_ERROR_DOMAIN, FB_ERROR_CONN,
                         "error joining to Spread group %s: %s",
                         spread->groups[i].name, fbConnSpreadError( ret ) );
            return 0;
        }
    }

    do {
        ret = SP_receive( spread->recv_mbox, &service_type, sender,
                          spread->recv_max_groups, &num_groups,
                          (char (*)[])spread->recv_groups,
                          &mess_type, &endian_mismatch, spread->recv_max,
                          spread->recv_mess );

        if (spread->recv_exit)
        {
            SP_disconnect( spread->recv_mbox );
            continue;
        }
        if (ret < 0) {

            if (ret == GROUPS_TOO_SHORT) {
                g_free( spread->recv_groups );
                spread->recv_max_groups = -ret;
                spread->recv_groups = g_new0( sp_groupname_t,
                                              spread->recv_max_groups );
            } else if (ret == BUFFER_TOO_SHORT) {
                g_free( spread->recv_mess );
                spread->recv_max = -endian_mismatch;
                spread->recv_mess = g_new0( char, spread->recv_max );
            } else {
                g_set_error( &(spread->recv_err), FB_ERROR_DOMAIN, FB_ERROR_IO,
                             "error receiving Spread message: %s",
                             fbConnSpreadError( ret ) );

                SP_disconnect( spread->recv_mbox );

                run = 0;
            }
            continue;
        }
        /* actually received a message! Now process it */
        if (!Is_reg_memb_mess( service_type ) ||
            !Is_caused_join_mess( service_type ))
            continue;

        if (SP_get_memb_info( spread->recv_mess, service_type, &memb_info ) <0)
            continue;
        if (!memb_info.changed_member[0])
            continue;
        if (strncmp( memb_info.changed_member, spread->recv_privgroup,
                     MAX_GROUP_NAME ) == 0)
            continue;

        /** Send Relevant Templates to New Member only. */
        /** memb_info.changed_member is private group name */
        /** sender is group they are subscribing to */

        fbSessionSetPrivateGroup(spread->session,
                                 sender, memb_info.changed_member);

    } while (run);

    return 0;
}

/**
 * fbExporterSpreadOpen
 *
 * @param exporter
 * @param err
 */
static gboolean fbExporterSpreadOpen(
     fbExporter_t *exporter,
     GError **err )
{
    int ret;

    if (!exporter->spec.spread->daemon)
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread daemon name cannot be null" );
        return FALSE;
    }
    if (!exporter->spec.spread->daemon[0])
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread daemon name cannot be empty" );
        return FALSE;
    }
    /*if (strnlen( exporter->spec.spread->daemon, 262 ) > 261)*/
    if ( !(memchr( exporter->spec.spread->daemon, 0, 261 )) )
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread daemon name too long" );
        return FALSE;
    }
    if (!exporter->spec.spread->groups)
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread groups cannot be null" );
        return FALSE;
    }
    if (!exporter->spec.spread->groups[0].name[0])
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread groups cannot be empty" );
        return FALSE;
    }
    if (!exporter->spec.spread->session)
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "Spread session cannot be null" );
        return FALSE;
    }

    pthread_mutex_init( &(exporter->spec.spread->write_lock), 0 );

    ret = SP_connect( exporter->spec.spread->daemon, 0, 0, 0,
                      &(exporter->spec.spread->mbox),
                      exporter->spec.spread->privgroup );
    if (ret != ACCEPT_SESSION)
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "error connecting to Spread daemon %s: %s",
                     exporter->spec.spread->daemon, fbConnSpreadError( ret ) );
        return FALSE;
    }

    exporter->spec.spread->recv_err = 0;
    exporter->spec.spread->recv_exit = 0;
    ret = pthread_create( &(exporter->spec.spread->recv_thread), 0,
                          fbExporterSpreadReceiver, exporter );
    if (ret)
    {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "error creating Spread receiver thread: %s",
                     strerror( ret ) );
        SP_disconnect( exporter->spec.spread->mbox );
        return FALSE;
    }
    pthread_detach( exporter->spec.spread->recv_thread );

    exporter->active = TRUE;
    return TRUE;
}

/**
 * fbExporterSpreadWrite
 *
 * @param exporter
 * @param msg
 * @param msg size
 * @param err
 */
static gboolean fbExporterSpreadWrite(
    fbExporter_t *exporter,
    uint8_t *msgbase,
    size_t msglen,
    GError **err )
{
    int ret = 0;
    fbSpreadSpec_t *spread;

    pthread_mutex_lock( &(exporter->spec.spread->write_lock) );

    spread = exporter->spec.spread;

    if (spread->num_groups == 1) {
        ret = SP_multicast( spread->mbox, RELIABLE_MESS,
                            spread->groups[0].name,
                            0, msglen, (const char *)msgbase );
    } else if (spread->num_groups_to_send == 1) {
        ret = SP_multicast( spread->mbox, RELIABLE_MESS,
                            spread->groups_to_send[0].name,
                            0, msglen, (const char *)msgbase );
    } else if (spread->num_groups_to_send > 1) {
        ret = SP_multigroup_multicast( spread->mbox, RELIABLE_MESS,
                                       spread->num_groups_to_send,
                                      (const char (*)[])spread->groups_to_send,
                                       0, msglen, (const char *)msgbase );

    } else {
        ret = SP_multigroup_multicast( spread->mbox, RELIABLE_MESS,
                                       spread->num_groups,
                                       (const char (*)[])spread->groups,
                                       0, msglen, (const char *)msgbase );
    }

    if (ret < 0) {
        g_set_error( err, FB_ERROR_DOMAIN, FB_ERROR_CONN,
                     "error receiving Spread message: %s",
                     fbConnSpreadError( ret ) );
    }

    pthread_mutex_unlock( &(exporter->spec.spread->write_lock) );

    return (ret < 0) ? FALSE : TRUE;
}

/**
 * fbExporterSpreadClose
 *
 * @param exporter
 */

static void fbExporterSpreadClose(
    fbExporter_t *exporter )
{
    if (exporter->active)
    {
        pthread_cancel( exporter->spec.spread->recv_thread );
        SP_disconnect( exporter->spec.spread->mbox );
    }
    exporter->active = FALSE;
}

/**
 * fbExporterAllocSpread
 *
 * @param Spread_params
 */
fbExporter_t *fbExporterAllocSpread(
    fbSpreadParams_t *params )
{
    fbExporter_t    *exporter = NULL;

    if (!g_thread_supported( )) {
        g_thread_init( 0 );
    }

    g_assert( params->daemon );
    g_assert( params->groups );
    g_assert( params->groups[0] );

    exporter = g_slice_new0( fbExporter_t );
    memset( exporter, 0, sizeof( fbExporter_t ) );

    exporter->spec.spread = fbConnSpreadCopy( params);

    exporter->exopen = fbExporterSpreadOpen;
    exporter->exwrite = fbExporterSpreadWrite;
    exporter->exclose = fbExporterSpreadClose;
    #ifdef DEBUG
    exporter->mtu = 8192;
    #else
    exporter->mtu = FB_SPREAD_MTU;
    #endif

    return exporter;
}

/**
 * fbExporterSetGroupsToSend
 *
 * @param exporter
 * @param groups
 * @param num_groups
 *
 */
void fbExporterSetGroupsToSend(
    fbExporter_t      *exporter,
    char              **groups,
    int               num_groups)
{
    int n = 0;
    char **g = 0;
    fbSpreadSpec_t   *spread = exporter->spec.spread;

    if (!spread->groups_to_send) {
        spread->groups_to_send = g_new0(sp_groupname_t, spread->num_groups);
    }

    g = groups;

    for (n=0; n < num_groups; n++)
    {
        strncpy(spread->groups_to_send[n].name, *g, MAX_GROUP_NAME-1);
        g++;
    }

    spread->num_groups_to_send = n;
}

/**
 * fbExporterCheckGroups
 *
 * If we are sending to a new (different) group of Spread Groups - return TRUE
 * to emit the buffer and set new export groups.
 *
 * @param exporter
 * @param groups
 * @param num_groups
 */
gboolean fbExporterCheckGroups(
    fbExporter_t *exporter,
    char **groups,
    int    num_groups)
{
    int n;
    fbSpreadSpec_t *spread = exporter->spec.spread;

    if (num_groups != spread->num_groups_to_send) {
        return TRUE;
    }

    for (n = 0; n < num_groups; n++) {
        if (strcmp(spread->groups_to_send[n].name, groups[n]) != 0) {
            return TRUE;
        }
    }

    return FALSE;

}

#endif /* HAVE_SPREAD */

/**
 *fbExporterSetStream
 *
 * @param exporter
 * @param sctp_stream
 *
 */
void fbExporterSetStream(
    fbExporter_t        *exporter,
    int                 sctp_stream)
{
    exporter->sctp_mode &= ~FB_F_SCTP_AUTOSTREAM;
    exporter->sctp_stream = sctp_stream;
}

/**
 *fbExporterAutoStream
 *
 * @param exporter
 *
 *
 */
void fbExporterAutoStream(
    fbExporter_t        *exporter)
{
    exporter->sctp_mode |= FB_F_SCTP_AUTOSTREAM;
}

/**
 *fbExporterSetPRTTL
 *
 * @param exporter
 * @param pr_ttl
 *
 *
 */
void fbExporterSetPRTTL(
    fbExporter_t        *exporter,
    int                 pr_ttl)
{
    if (pr_ttl > 0) {
        exporter->sctp_mode |= FB_F_SCTP_PR_TTL;
        exporter->sctp_pr_param = pr_ttl;
    } else {
        exporter->sctp_mode &= ~FB_F_SCTP_PR_TTL;
        exporter->sctp_pr_param = 0;
    }
}

/**
 *fbExportMessage
 *
 *
 * @param exporter
 * @param msgbase
 * @param msglen
 * @param err
 *
 * @return
 *
 */
gboolean        fbExportMessage(
    fbExporter_t    *exporter,
    uint8_t         *msgbase,
    size_t          msglen,
    GError          **err)
{
    /* Ensure stream is open */
    if (!exporter->active) {
        g_assert(exporter->exopen);
        if (!exporter->exopen(exporter, err)) return FALSE;
    }

    /* Attempt to write message */
    if (exporter->exwrite(exporter, msgbase, msglen, err)) return TRUE;

    /* Close exporter on write failure */
    if (exporter->exclose) exporter->exclose(exporter);
    return FALSE;
}

/**
 *fbExporterFree
 *
 *
 * @param exporter
 *
 */
void                fbExporterFree(
    fbExporter_t       *exporter)
{
    fbExporterClose(exporter);
    if (exporter->exwrite == fbExporterWriteFile)
    {
        g_free(exporter->spec.path);
    }
    #ifdef HAVE_SPREAD
    else if (exporter->exwrite == fbExporterSpreadWrite)
    {
        fbConnSpreadFree( exporter->spec.spread );
    }
    #endif
    else
        fbConnSpecFree(exporter->spec.conn);

    g_slice_free(fbExporter_t, exporter);
}

/**
 *fbExporterClose
 *
 *
 *
 * @param exporter
 */
void fbExporterClose(
    fbExporter_t    *exporter)
{
    if (exporter->active && exporter->exclose) exporter->exclose(exporter);
}
