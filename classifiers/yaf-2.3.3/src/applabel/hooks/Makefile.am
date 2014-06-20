## Process this file with automake to produce Makefile.in
## ------------------------------------------------------------------------
## Makefile.am (source)
## autotools build system for YAF
## ------------------------------------------------------------------------
## Copyright (C) 2012-2013 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: Chris Inacio <inacio@cert.org>
## ------------------------------------------------------------------------
## GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------


AM_CFLAGS = -Wall

pkglib_LTLIBRARIES = dpacketplugin.la dhcp_fp_plugin.la

dpacketplugin_la_SOURCES = dpacketplugin.c dpacketplugin.h
dpacketplugin_la_LDFLAGS = -version-info @version_info@ -module
dpacketplugin_la_CFLAGS = -I${top_srcdir}/include -I${top_srcdir}/src/applabel @GLIB_CFLAGS@ @libfixbuf_CFLAGS@ 

if CYGWIN
dpacketplugin_la_CFLAGS += -DYAF_CONF_DIR='yfGetCygwinConfDir()'
else
dpacketplugin_la_CFLAGS += -DYAF_CONF_DIR='"$(sysconfdir)"'
endif

dhcp_fp_plugin_la_SOURCES = dhcp_fp_plugin.c
dhcp_fp_plugin_la_LDFLAGS = -version-info @version_info@ -module
dhcp_fp_plugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

if CYGWIN
dhcp_fp_plugin_la_CFLAGS += -DYAF_CONF_DIR='yfGetCygwinConfDir()'
else
dhcp_fp_plugin_la_CFLAGS += -DYAF_CONF_DIR='"$(sysconfdir)"'
endif
