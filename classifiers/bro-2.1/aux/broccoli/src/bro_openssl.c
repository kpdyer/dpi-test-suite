/*
       B R O C C O L I  --  The Bro Client Communications Library

Copyright (C) 2004-2008 Christian Kreibich <christian (at) icir.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies of the Software and its documentation and acknowledgment shall be
given in the documentation and software packages that this Software was
used.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/
#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <netdb.h>

#ifdef __MINGW32__
#include <winsock.h>
#else
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netinet/in.h>
#endif

#ifdef __EMX__
#include <sys/select.h>
#endif 

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <broccoli.h>
#include <bro_types.h>
#include <bro_debug.h>
#include <bro_config.h>
#include <bro_openssl.h>

/* PLEASE NOTE: this file deals with handling I/O through OpenSSL in
 * an unencrypted and an encrypted fashion. There are no ifdefs for one
 * mode or the other, because using OpenSSL connection abstraction helps
 * portability so we always use OpenSSL, even when not encryting traffic.
 *
 * Encryption is automatically attempted if the certificate files can be
 * read from configuration items "/broccoli/host_cert" and "/broccoli/ca_cert".
 * (Note that when Bro peers communicate over an encrypted channel, they
 * both need to certify themselves).
 *
 * Much of the code here is from the O'Reilly book on OpenSSL, by Viega,
 * Messier, and Chandra. However the problem with their example application
 * is that they use SSL_read/SSL_write, thus losing the transparency of
 * the generic BIO_... functions regarding the use of encryption (we do
 * allow for plaintext communication as well). Since I don't want to write
 * duplicate code for the encrypted and unencrypted traffic, a socket
 * BIO is always used and, in the case of encryption, that is simply
 * appended to an SSL BIO.
 *
 * We currently do not support the following:
 * - ephemeral keying.
 * - session caching.
 *
 * I haven't specifically looked at whether this code supports session
 * renegotiation.
 */

/* Broccoli initialization context; defined in bro.c. */
extern const BroCtx *global_ctx;

/* The connection creation context. If this context is NULL,
 * it means we are not using encryption.
 */
static SSL_CTX *ctx = NULL;

#ifdef BRO_DEBUG
static void
print_errors(void)
{
  if (bro_debug_messages)
    {
      D(("OpenSSL error dump:\n"));
      if (ERR_peek_error() == 0)
	fprintf(stdout, "--> %s\n", strerror(errno));
      else
	ERR_print_errors_fp(stdout);
    }
}
#else
#define print_errors()
#endif


static int
verify_cb(int ok, X509_STORE_CTX *store)
{
  char data[256];
  int depth, err;
  X509 *cert;

  if (ok)
    return ok;

  cert = X509_STORE_CTX_get_current_cert(store);
  depth = X509_STORE_CTX_get_error_depth(store);
  err = X509_STORE_CTX_get_error(store);
  
  D(("Handshake failure: verification problem at depth %i:\n", depth));
  X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
  D(("  issuer  = %s\n", data));
  X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
  D(("  subject = %s\n", data));
  D(("  error code %i: %s\n", err, X509_verify_cert_error_string(err)));
  
  return ok;
}


static int
prng_init_file(char *file)
{
  struct stat st;
  int fd, flags, i;
  uchar buf[1024];
  
  /* Check if file  is available, and try to seed the PRNG
   * from it. If things fail, do nothing and rely on OpenSSL to
   * initialize from /dev/urandom.
   */
  
  if (stat(file, &st) != 0)
    {
      D(("%s does not exist, not seeding from it.\n", file));
      return FALSE;
    }
    
  /* Now we need to figure out how much entropy the device
   * can provide. We try to read 1K, and accept if it can
   * read at least 256 bytes.
   */
  if ( (fd = open(file, O_RDONLY)) < 0)
    {
      D(("Could not read from %s.\n", file));
      return FALSE;
    }
    
  if ( (flags = fcntl(fd, F_GETFL, 0)) < 0)
    {
      D(("can't obtain socket flags: %s", strerror(errno)));
      close(fd);
      return FALSE;
    }
  
  if ( fcntl(fd, F_SETFL, flags|O_NONBLOCK) < 0 )
    {
      D(("can't set fd to non-blocking: %s.", strerror(errno)));
      close(fd);
      return FALSE;
    }
    
  if ( (i = read(fd, buf, 1024)) < 256)
    {
      D(("Could only read %i bytes from %s, not enough.\n", i, file));
      close(fd);
      return FALSE;
    }
  
  D(("Seeding PRNG from %s, using %i bytes.\n", file, i));
  close(fd);
  RAND_seed(buf, i);
  
  return TRUE;
}



static void
prng_init(void)
{
  static int deja_vu = FALSE;
  
  if (deja_vu)
    return;
  
  if (prng_init_file("/dev/random"))
    {
      deja_vu = TRUE;
      return;
    }

  if (prng_init_file("/dev/urandom"))
    {
      deja_vu = TRUE;
      return;
    }
  
  D(("*** CAUTION: Unable to initialize random number generator ***\n"));
}


static int
pem_passwd_cb(char *buf, int size, int rwflag, void *pass)
{
  /* Note that if |pass| < size, the remainder in buf will be
   * zero-padded by strncpy().
   */
  strncpy(buf, (char *) pass, size);
  buf[size - 1] = '\0';

  return strlen(buf);
  rwflag = 0;
}

int
__bro_openssl_init(void)
{
  static int deja_vu = FALSE;
  int use_ssl = FALSE;
  const char *our_cert, *our_key, *our_pass, *ca_cert;
  
  D_ENTER;

  if (deja_vu)
    D_RETURN_(TRUE);

  deja_vu = TRUE;

  /* I hope these should go before SSL_library_init() -- not even the
   * O'Reilly book is clear on that. :( --cpk
   */
  if (global_ctx)
    {
      if (global_ctx->id_func)
	CRYPTO_set_id_callback(global_ctx->id_func);
      if (global_ctx->lock_func)
	CRYPTO_set_locking_callback(global_ctx->lock_func);
      if (global_ctx->dl_create_func)
	CRYPTO_set_dynlock_create_callback(global_ctx->dl_create_func);
      if (global_ctx->dl_lock_func)
	CRYPTO_set_dynlock_lock_callback(global_ctx->dl_lock_func);
      if (global_ctx->dl_free_func)
	CRYPTO_set_dynlock_destroy_callback(global_ctx->dl_free_func);
    }
  
  SSL_library_init();
  prng_init();
  
#ifdef BRO_DEBUG
  D(("Loading OpenSSL error strings for debugging\n"));
  SSL_load_error_strings();
#endif

  if (__bro_conf_get_int("/broccoli/use_ssl", &use_ssl) && ! use_ssl)
    {
      D(("SSL disabled in configuration, not using SSL.\n"));
      D_RETURN_(TRUE);
    }

  our_cert = __bro_conf_get_str("/broccoli/host_cert");
  our_key = __bro_conf_get_str("/broccoli/host_key");
  if (our_key == NULL)
    {
    /* No private key configured; get it from the certificate file */
    our_key = our_cert;
    }

  if (our_cert == NULL)
    {
      if (use_ssl)
	{
	  D(("SSL requested but host certificate not given -- aborting.\n"));
	  D_RETURN_(FALSE);
	}
      else
	{
	  D(("use_ssl not used and host certificate not given -- not using SSL.\n"));
	  D_RETURN_(TRUE);
	}
    }

  if (our_key == NULL)
    {
      if (use_ssl)
	{
	  D(("SSL requested but host key not given -- aborting.\n"));
	  D_RETURN_(FALSE);
	}
      else
	{
	  D(("use_ssl not used and host key not given -- not using SSL.\n"));
	  D_RETURN_(TRUE);
	}
    }


  /* At this point we either haven't seen use_ssl but a host_cert, or
   * we have seen use_ssl and it is set to true. Either way, we attempt
   * to set up an SSL connection now and abort if this fails in any way.
   */

  if (! (ctx = SSL_CTX_new(SSLv3_method())))
    D_RETURN_(FALSE);
  
  /* We expect things to be stored in PEM format, which means that we
   * can store multiple entities in one file. In this case, our own
   * certificate is expected to be stored along with the private key
   * in the file pointed to by preference setting /broccoli/certificate.
   *
   * See page 121 in O'Reilly's OpenSSL book for details.
   */
  if (SSL_CTX_use_certificate_chain_file(ctx, our_cert) != 1)
    {
      D(("Error loading certificate from '%s'.\n", our_cert));
      goto error_return;
    }
  
  if ( (our_pass = __bro_conf_get_str("/broccoli/host_pass")))
    {
      D(("Host passphrase given in config file, not prompting for input.\n"));
      SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
      SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *) our_pass);
    }
  
  if (SSL_CTX_use_PrivateKey_file(ctx, our_key, SSL_FILETYPE_PEM) != 1)
    {
      D(("SSL used but error loading private key from '%s' -- aborting.\n", our_key));
      goto error_return;
    }
  
  /* We should not need the passphrase, if existant, ever again.
   * Therefore we erase it from memory now.
   */
  if (our_pass)
    {
      our_pass = NULL;
      __bro_conf_forget_item("/broccoli/host_pass");
    }

  /* For validation purposes, our trusted CA's certificate will
   * be needed as well:
   */
  if (! (ca_cert = __bro_conf_get_str("/broccoli/ca_cert")))
    {
      D(("SSL used but CA certificate not given -- aborting."));
      goto error_return;
    }
  
  if (! SSL_CTX_load_verify_locations(ctx, ca_cert, 0))
    {
      D(("SSL used but CA certificate could not be loaded -- aborting\n"));
      goto error_return;
    }
  
  /* Check the consistency of the certificate vs. the private key */
  if (SSL_CTX_check_private_key(ctx) != 1)
    {
      D(("SSL used but private key does not match the certificate -- aborting\n"));
      goto error_return;
    }
  
  /* Only use real ciphers.
   */
  if (! SSL_CTX_set_cipher_list(ctx, "HIGH"))
    {
      D(("SSL used but can't set cipher list -- aborting\n"));
      goto error_return;
    }
  
  /* We require certificates from all communication peers, regardless of
   * whether we're the "server" or "client" (these concepts are blurred in our
   * case anyway). In order to be able to give better error feedback, we
   * add our own verification filter callback, "verify_cb".
   */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		     verify_cb);
  
  D(("SSL setup successful.\n"));
  D_RETURN_(TRUE);
  
 error_return:
  SSL_CTX_free(ctx);
  ctx = NULL;
  D_RETURN_(FALSE);
}

int
__bro_openssl_rand_bytes(u_char *buf, int num)
{
  if (! buf || num <= 0)
    return FALSE;

  /* Make sure PRNG is initialized; has effect only once. */
  prng_init();

  if (RAND_bytes(buf, num) > 0)
    return TRUE;
  
  RAND_pseudo_bytes(buf, num);
  return TRUE;
}


int
__bro_openssl_encrypted(void)
{
  return ctx != NULL;
}

static int
try_connect(const char* host_and_port)
	{
	int status, sockfd = -1;
	char* colon;
	char* tmp;
	char host[512];
	char port[16];
	struct addrinfo hints, *res, *res0;

	D_ENTER;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;

	if ( ! (tmp = strdup(host_and_port)) )
		{
		D(("Out of memory.\n"));
		D_RETURN_(-1);
		}

	if ( ! (colon = strrchr(tmp, ':')) )
		{
		D(("Invalid host:port string: %s\n", host_and_port));
		free(tmp);
		D_RETURN_(-1);
		}

	if ( ! colon[1] )
		{
		D(("Invalid port in host:port string: %s\n", host_and_port));
		free(tmp);
		D_RETURN_(-1);
		}

	*colon = '\0';
	__bro_util_snprintf(host, sizeof(host), "%s", tmp);
	__bro_util_snprintf(port, sizeof(port), "%s", colon + 1);
	free(tmp);

	D(("Trying to connect to [%s]:%s\n", host, port));

	status = getaddrinfo(host, port, &hints, &res0);
	if ( status != 0 )
		{
		D(("Error in getaddrinfo: %s\n", gai_strerror(status)));
		D_RETURN_(-1);
		}

	for ( res = res0; res; res = res->ai_next )
		{
		sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if ( sockfd < 0 )
			{
			D(("socket() failed: %s\n", strerror(errno)));
			continue;
			}

		if ( connect(sockfd, res->ai_addr, res->ai_addrlen) < 0 )
			{
			D(("connect() to %s failed: %s\n", host_and_port, strerror(errno)));
			close(sockfd);
			sockfd = -1;
			continue;
			}

		break;
		}

	freeaddrinfo(res0);
	D_RETURN_(sockfd);
	}

static int
openssl_connect(BroConn *bc)
{
  int flags, sockfd = -1;
  BIO *bio = NULL;
  BIO *ssl_bio = NULL;

  D_ENTER;

  if (! bc || ! bc->peer || ! *(bc->peer))
    D_RETURN_(FALSE);
  
  /* Make sure OpenSSL is initialised -- this has effect only once */
  if (! __bro_openssl_init())
    D_RETURN_(FALSE);

	/* Use socket provided by user if BroConn came via bro_conn_new_socket */
	if ( bc->socket >= 0 )
		{
		D(("Connection created from externally provided socket.\n"));
		sockfd = bc->socket;
		}
	else
		sockfd = try_connect(bc->peer);

	if ( sockfd == -1 )
		{
		D(("Error connecting to %s.\n", bc->peer));
		goto err_return;
		}

	if ( ! (bio = BIO_new_socket(sockfd, BIO_CLOSE)) )
		{
		D(("Error creating connection BIO from socket.\n"));
		goto err_return;
		}

	if ( (flags = fcntl(sockfd, F_GETFL, 0)) < 0 )
		{
		D(("Error getting socket flags.\n"));
		goto err_return;
		}

	if ( fcntl(sockfd, F_SETFL, flags|O_NONBLOCK) < 0 )
		{
		D(("Error setting socket to non-blocking.\n"));
		goto err_return;
		}

	/* Don't know whether this is needed but it does not hurt either. 
	 * It is however not sufficient to just call this; we manually need to
	 * set the socket to non-blocking as done above. */
	BIO_set_nbio(bio, 1);

	/* Add SSL if available */
	if ( ctx )
		{
		if ( ! (ssl_bio = BIO_new_ssl(ctx, 1)) )
			{
			D(("Error creating ssl BIO.\n"));
			goto err_return;
			}
		BIO_set_close(ssl_bio, BIO_CLOSE);
		BIO_push(ssl_bio, bio);
		bio = ssl_bio;
		}

	bc->bio = bio;
	D(("Connection established successfully.\n"));
	D_RETURN_(TRUE);

 err_return:

  print_errors();

#ifdef BRO_DEBUG
  if (ctx)
    D(("--- SSL CONNECTION SETUP FAILED. ---"));
  else
    D(("--- CLEARTEXT CONNECTION SETUP FAILED. ---"));
#endif  

  if (bio)
    BIO_free_all(bio);
  
  bc->state->rx_dead = bc->state->tx_dead = TRUE;
  bc->bio = NULL;
  D_RETURN_(FALSE);
}


int
__bro_openssl_connect(BroConn *bc)
{
  return openssl_connect(bc);
}

int
__bro_openssl_reconnect(BroConn *bc)
{
  return openssl_connect(bc);
}


void
__bro_openssl_shutdown(BroConn *bc)
{
  if (!bc || !bc->bio)
    return;
  
  if (getpid() != bc->id_pid)
    return;
  
  if (bc->state->rx_dead)
    return;
  
  bc->state->rx_dead = bc->state->tx_dead = TRUE;
  
  BIO_flush(bc->bio);
  BIO_free_all(bc->bio);
  bc->bio = NULL;
}


int       
__bro_openssl_read(BroConn *bc, uchar *buf, uint buf_size)
{
  int n;

  D_ENTER;
  
  /* It's important here to use <= for comparison, since, as the
   * invaluable O'Reilly OpenSSL book reports, "for each of the four
   * reading and writing functions, a 0 or -1 return value may or may
   * not necessarily indicate that an error has occurred." This may or
   * may not necessarily be indicative of the incredible PITA that
   * OpenSSL is. --cpk
   */
  if ( (n = BIO_read(bc->bio, buf, buf_size)) <= 0)
    {
      if (BIO_should_retry(bc->bio))
	D_RETURN_(0);
      
      __bro_openssl_shutdown(bc);
      D(("Connection closed, BIO_read() returned %i.\n", n));      
      print_errors();
      D_RETURN_(-1);
    }
    
  D_RETURN_(n);
}


int
__bro_openssl_write(BroConn *bc, uchar *buf, uint buf_size)
{
  int n;
  void *old_sig;
  
  D_ENTER;
  
#ifdef BRO_DEBUG
  if (bro_debug_messages)
    {
      unsigned int i = 0;
      int last_hex = 0;

      D(("Sending %u bytes: ", buf_size));
 
      for (i = 0; i < buf_size; i++)
	{
	  if (buf[i] >= 32 && buf[i] <= 126)
	    {
	      printf("%s%c", last_hex ? " " : "", buf[i]);
	      last_hex = 0;
	    }
	  else
	    {
	      printf(" 0x%.2x", buf[i]);
	      last_hex = 1;
	    }
	}
      printf("\n");
    }
#endif

  /* We may get a SIGPIPE if we write to a connection whose peer
   * died. Since we don't know the application context in which
   * we're running, we temporarily set the SIGPIPE handler to our
   * own and then set it back to the old one after we wrote.
   */
  old_sig = signal(SIGPIPE, SIG_IGN);
  
  n = BIO_write(bc->bio, buf, buf_size);
  
  if (n <= 0)
    {
      if (BIO_should_retry(bc->bio))
	{
	  n = 0;
	  goto error_return;
	}

      print_errors();
      __bro_openssl_shutdown(bc);
      D(("Connection closed.\n"));
      n = -1;
    }
  
  BIO_flush(bc->bio);

 error_return:
  
  if (old_sig != SIG_ERR)
    signal(SIGPIPE, old_sig);
  
  D_RETURN_(n);
}
