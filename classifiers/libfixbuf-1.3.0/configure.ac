dnl Process this file with autoconf to produce a configure script
dnl ------------------------------------------------------------------------
dnl configure.ac
dnl autotools build system for libfixbuf
dnl ------------------------------------------------------------------------
dnl Copyright (C) 2005-2013 Carnegie Mellon University. All Rights Reserved.
dnl ------------------------------------------------------------------------
dnl Authors: Brian Trammell, Dan Ruef <druef@cert.org>, Chris Inacio 
dnl <inacio@cert.org>
dnl ------------------------------------------------------------------------
dnl GNU Lesser GPL Rights pursuant to Version 2.1, February 1999
dnl Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
dnl ------------------------------------------------------------------------

dnl RCSIDENT("$Id: configure.in 18509 2012-08-23 19:13:27Z ecoff_svn $")

AC_INIT([libfixbuf], [1.3.0], [netsa-help@cert.org], [libfixbuf])
AC_CONFIG_AUX_DIR([autoconf])
AC_COPYRIGHT([Copyright (C) 2006-2012 by Carnegie Mellon University
GNU Public License (GPL) Rights pursuant to Version 2, June 1991
Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013])

AM_INIT_AUTOMAKE([1.6.3 foreign])

dnl change this version number every new release. (1:0:0 starts at 1.3.0)
dnl the first number should be changed if the interface has changed
dnl the second number should be changed for bug fixes, small changes
dnl the third number should be changed if the first number changes and 
dnl the release is backwards compatible with the previous release.

LIBCOMPAT="1:0:0"

AC_REVISION($Revision: 18509 $)
AM_CONFIG_HEADER(include/fixbuf/config.h)
AC_CONFIG_MACRO_DIR([m4])
AM_PROG_LIBTOOL

AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_HEADER_STDC
AC_LANG_C

CPPFLAGS='-I$(top_builddir)/include -I$(top_srcdir)/include'" $CPPFLAGS"

AC_HEADER_STDC
AC_CHECK_HEADERS([unistd.h stdint.h errno.h netinet/in.h sys/errno.h sys/socket.h])

AM_WITH_DMALLOC

m4_include([autoconf/debug.m4])
AC_DEBUG

RPM_CONFIG_FLAGS=""

dnl ----------------------------------------------------------------------
dnl Set up doxygen
dnl ----------------------------------------------------------------------
m4_include([autoconf/ax_prog_doxygen.m4])

DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(libfixbuf, Doxyfile, doc)

dnl ----------------------------------------------------------------------
dnl Check for aligned access required
dnl ----------------------------------------------------------------------

m4_include([autoconf/ax_check_aligned_access_required.m4])

AX_CHECK_ALIGNED_ACCESS_REQUIRED

dnl ----------------------------------------------------------------------
dnl Check for a suitable glib
dnl ----------------------------------------------------------------------

GLIB_PRESENT=NO
GLIB_LDADD=

AM_PATH_GLIB_2_0([2.4.7],[GLIB_PRESENT=YES],,[gthread])

AC_ARG_WITH(glib-static,
[  --with-glib-static=prefix   use static glib tree],[
GLIB_STATIC_LIBGLIB2_A="${withval}/lib/libglib-2.0.a ${withval}/lib/libgthread-2.0.a"
GLIB_STATIC_INCLUDE="${withval}/include/glib-2.0"
GLIB_STATIC_LIBINCLUDE="${withval}/lib/glib-2.0/include"
if test -f ${GLIB_STATIC_LIBGLIB2_A}; then
    if test -f "${GLIB_STATIC_INCLUDE}/glib.h"; then
        GLIB_LDADD=${GLIB_STATIC_LIBGLIB2_A}
        GLIB_CFLAGS="-I${GLIB_STATIC_INCLUDE} -I${GLIB_STATIC_LIBINCLUDE}"
        AC_SUBST(GLIB_LIBS)
        AC_SUBST(GLIB_CFLAGS)
        GLIB_PRESENT=YES
        AC_MSG_NOTICE([assuming static glib in ${withval} is good...])
    fi
fi
])

if test x"$GLIB_PRESENT" != "xYES"; then
  AC_MSG_ERROR([Cannot find a suitable glib2 (>= 2.4.7)])
fi

AC_SUBST(GLIB_LDADD)

dnl ----------------------------------------------------------------------
dnl Check for getaddrinfo
dnl ----------------------------------------------------------------------

AC_CHECK_FUNCS(getaddrinfo)



dnl ----------------------------------------------------------------------
dnl check for all of the Solaris specific libraries
dnl ----------------------------------------------------------------------
AC_SEARCH_LIBS([nanosleep], [rt])
AC_SEARCH_LIBS([inet_ntoa], [nsl])
AC_SEARCH_LIBS([socket], [socket])


dnl ----------------------------------------------------------------------
dnl Check for SCTP support
dnl ----------------------------------------------------------------------

AC_ARG_WITH(sctp,
AC_HELP_STRING([--with-sctp=prefix], [Enable SCTP support using libsctp]),[
if test "x$withval" != "xno"; then

  if test -d ${withval}; then
    LDFLAGS="-L${withval}/lib ${LDFLAGS}"
    CFLAGS="-I{withval}/include ${CFLAGS}"
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-sctp=${withval}"
  else
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-sctp"
  fi

dnl look for libsctp
    AC_CHECK_LIB(sctp, sctp_sendmsg,[
        AC_DEFINE(FB_ENABLE_SCTP, 1, [Define to 1 to enable SCTP support])
        LIBS="-lsctp ${LIBS}"
        AC_SUBST(FIXBUF_REQ_LIBSCTP, [1])
    ],[
        AC_MSG_ERROR([--with-sctp given but cannot find libsctp])
    ])

dnl look for SCTP header files
    AC_CHECK_HEADER(netinet/sctp.h,[
        AC_DEFINE(FB_INCLUDE_SCTP_H, 1, 
                 [Define to 1 to use sctp.h header])
        AC_SUBST(FIXBUF_REQ_SCTPDEV, [1])
    ], [], [AC_INCLUDES_DEFAULT([
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
])])

    AC_CHECK_HEADER(netinet/sctp_uio.h,[
        AC_DEFINE(FB_INCLUDE_SCTP_UIO_H, 1, 
                 [Define to 1 to use sctp_uio.h header])
    ])
fi
])


dnl ----------------------------------------------------------------------
dnl Check for OpenSSL TLS and DTLS support
dnl ----------------------------------------------------------------------

AC_ARG_WITH(openssl,
AC_HELP_STRING([--with-openssl=prefix], [Use OpenSSL for TLS/DTLS support]),[
if test -d ${withval}; then
    LDFLAGS="-L${withval}/lib ${LDFLAGS}"
    CFLAGS="-I{withval}/include ${CFLAGS}"
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-openssl=${withval}"
else
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-openssl"
fi


dnl look for libssl
    AC_CHECK_LIB(ssl,SSL_new,[
        AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 to enable OpenSSL support])
        LIBS="-lssl -lcrypto ${LIBS}"
        AC_SUBST(FIXBUF_REQ_LIBSSL, [1])
    ],[
        AC_MSG_ERROR([--with-openssl given but cannot find SSL_new()])
    ])

dnl look for dtls
    AC_CHECK_LIB(ssl,DTLSv1_method,[
        AC_DEFINE(HAVE_OPENSSL_DTLS, 1, [Define to 1 to enable DTLS support])
    ],[
        AC_MSG_NOTICE([OpenSSL does not support DTLS])
    ])

    AC_CHECK_HEADER(openssl/ssl.h,[],
    [
       AC_MSG_ERROR([--with-openssl given but cannot find libssl headers.])
    ])

])

dnl ----------------------------------------------------------------------
dnl Check for Spread support
dnl ----------------------------------------------------------------------

m4_include([autoconf/spread.m4])
AC_PATH_SPREAD([4.1])

AC_SUBST(LIBCOMPAT)
AC_SUBST(RPM_CONFIG_FLAGS)

dnl automake 1.9 doesn't substitute these automatically, so we do it ourselves
dnl just in case
AC_SUBST([abs_top_srcdir])
AC_SUBST([abs_top_builddir])

AC_OUTPUT([
    Makefile
    src/Makefile
    include/Makefile
    libfixbuf.pc
    libfixbuf.spec
    Doxyfile])
