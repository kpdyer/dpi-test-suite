## Process this file with automake to produce Makefile.in
## ------------------------------------------------------------------------
## Makefile.am (source)
## autotools build system for YAF
## ------------------------------------------------------------------------
## Copyright (C) 2013 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: Chris Inacio <inacio@cert.org>
## ------------------------------------------------------------------------
## GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------


AM_CFLAGS = -Wall

pkglib_LTLIBRARIES = nullplugin.la dnsplugin.la tlsplugin.la slpplugin.la dumpplugin.la ircplugin.la pptpplugin.la nntpplugin.la tftpplugin.la mysqlplugin.la pop3plugin.la teredoplugin.la snmpplugin.la aolplugin.la socksplugin.la bgpplugin.la dhcpplugin.la piplugin.la rtpplugin.la palplugin.la proxyplugin.la

nullplugin_la_SOURCES = nullplugin.c
nullplugin_la_LDFLAGS = -version-info @version_info@ -module
nullplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@ 

dnsplugin_la_SOURCES = dnsplugin.c
dnsplugin_la_LDFLAGS = -version-info @version_info@ -module
dnsplugin_la_CFLAGS = -I${top_srcdir}/include -I${top_srcdir}/src/applabel @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

tlsplugin_la_SOURCES = tlsplugin.c
tlsplugin_la_LDFLAGS = -version-info @version_info@ -module
tlsplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

slpplugin_la_SOURCES = slpplugin.c
slpplugin_la_LDFLAGS = -version-info @version_info@ -module
slpplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

dumpplugin_la_SOURCES = outputDumper.c
dumpplugin_la_LDFLAGS = -version-info @version_info@ -module
dumpplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

ircplugin_la_SOURCES = ircplugin.c
ircplugin_la_LDFLAGS = -version-info @version_info@ -module
ircplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

pptpplugin_la_SOURCES = pptpplugin.c
pptpplugin_la_LDFLAGS = -version-info @version_info@ -module
pptpplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

nntpplugin_la_SOURCES = nntpplugin.c
nntpplugin_la_LDFLAGS = -version-info @version_info@ -module
nntpplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

tftpplugin_la_SOURCES = tftpplugin.c
tftpplugin_la_LDFLAGS = -version-info @version_info@ -module
tftpplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

mysqlplugin_la_SOURCES = mysqlplugin.c
mysqlplugin_la_LDFLAGS = -version-info @version_info@ -module
mysqlplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

pop3plugin_la_SOURCES = pop3plugin.c
pop3plugin_la_LDFLAGS = -version-info @version_info@ -module
pop3plugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

teredoplugin_la_SOURCES = teredoplugin.c
teredoplugin_la_LDFLAGS = -version-info @version_info@ -module
teredoplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

snmpplugin_la_SOURCES = snmpplugin.c
snmpplugin_la_LDFLAGS = -version-info @version_info@ -module
snmpplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

aolplugin_la_SOURCES = aolplugin.c
aolplugin_la_LDFLAGS = -version-info @version_info@ -module
aolplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

socksplugin_la_SOURCES = socksplugin.c
socksplugin_la_LDFLAGS = -version-info @version_info@ -module
socksplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

bgpplugin_la_SOURCES = bgpplugin.c
bgpplugin_la_LDFLAGS = -version-info @version_info@ -module
bgpplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

dhcpplugin_la_SOURCES = dhcpplugin.c
dhcpplugin_la_LDFLAGS = -version-info @version_info@ -module
dhcpplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

piplugin_la_SOURCES = piplugin.c
piplugin_la_LDFLAGS = -version-info @version_info@ -module
piplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

rtpplugin_la_SOURCES = rtpplugin.c
rtpplugin_la_LDFLAGS = -version-info @version_info@ -module
rtpplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

palplugin_la_SOURCES = palplugin.c
palplugin_la_LDFLAGS = -version-info @version_info@ -module
palplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

proxyplugin_la_SOURCES = proxyplugin.c
proxyplugin_la_LDFLAGS = -version-info @version_info@ -module
proxyplugin_la_CFLAGS = -I${top_srcdir}/include @GLIB_CFLAGS@ @libfixbuf_CFLAGS@
