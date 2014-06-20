## Process this file with automake to produce Makefile.in
## ------------------------------------------------------------------------
## Makefile.am (source)
## autotools build system for YAF
## ------------------------------------------------------------------------
## Copyright (C) 2006-2013 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: Emily Sarneso
## ------------------------------------------------------------------------
## GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------

PODFILES = getFlowKeyHash.pod yafMeta2Pcap.pod
man1_MANS = getFlowKeyHash.1 yafMeta2Pcap.1

bin_PROGRAMS = getFlowKeyHash yafMeta2Pcap

.pod.1:
	$(POD2MAN) $(YAF_POD2MAN_ARGS) --section=1 $< $@

.pod.html:
	$(POD2HTML) --noindex --infile="$<" --outfile="$@"
	$(top_srcdir)/doc/add-header.pl "$@"

CLEANFILES = $(man1_MANS)

EXTRA_DIST = $(PODFILES)

getFlowKeyHash_SOURCES = getFlowKeyHash.c
getFlowKeyHash_LDFLAGS = @GLIB_LIBS@ -L../airframe/src -lairframe
getFlowKeyHash_CFLAGS = @GLIB_CFLAGS@

yafMeta2Pcap_SOURCES = yafMeta2Pcap.c
yafMeta2Pcap_LDFLAGS = @GLIB_LIBS@
yafMeta2Pcap_CFLAGS = @GLIB_CFLAGS@


