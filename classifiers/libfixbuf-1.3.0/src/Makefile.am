## Process this file with automake to produce Makefile.in
## ------------------------------------------------------------------------
## Makefile.am (source)
## autotools build system for libfixbuf
## ------------------------------------------------------------------------
## Copyright (C) 2005-2013 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: Brian Trammell
## ------------------------------------------------------------------------
## GNU Lesser GPL Rights pursuant to Version 2.1, February 1999
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------

lib_LTLIBRARIES = libfixbuf.la

WARN_CFLAGS = -g -DDEBUG -Wall

libfixbuf_la_SOURCES =  fbuf.c       fbinfomodel.c fbtemplate.c  fbsession.c \
                        fbconnspec.c fbexporter.c  fbcollector.c fblistener.c \
						fbnetflow.c
libfixbuf_la_LIBADD = $(GLIB_LDADD)
libfixbuf_la_LDFLAGS = $(SPREAD_LDFLAGS) $(SPREAD_LIBS) $(GLIB_LIBS) -version-info $(LIBCOMPAT)
libfixbuf_la_CFLAGS = $(WARN_CFLAGS) $(DEBUG_CFLAGS) $(SPREAD_CFLAGS) $(GLIB_CFLAGS)

noinst_HEADERS = fbcollector.h
