## Process this file with automake to produce Makefile.in

## ------------------------------------------------------------------------
## Makefile.am (toplevel)
## autotools build system for libfixbuf
## ------------------------------------------------------------------------
## Copyright (C) 2005-2013 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: Brian Trammell
## ------------------------------------------------------------------------
## GNU Lesser GPL Rights pursuant to Version 2.1, February 1999
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------

SUBDIRS = src include
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libfixbuf.pc

include doxygen.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)

ACLOCAL_AMFLAGS = -I m4

release-note-doc: NEWS
	$(top_srcdir)/doc/news2xhtml.pl ${PACKAGE_TARNAME} lgpl 10 < $(top_srcdir)/NEWS > doc/releases.xml

make-doc-path:
	mkdir -p $(top_builddir)/doc/html

copy-doxygen-doc:
	cp -pr doc/html $(distdir)/doc

dist-hook: docs copy-doxygen-doc
	find $(distdir) -name .svn -type d -prune -exec rm -rf '{}' ';'

distclean-local:
	rm -f $(top_builddir)/doc/releases.xml

docs: make-doc-path doxygen-doc release-note-doc

EXTRA_DIST = \
     Doxyfile.in \
     libfixbuf.spec \
     libfixbuf.spec.in \
     doc/Doxyhead.html \
     doc/Doxyfoot.html \
     doc/doxygen.css \
     doc/news2xhtml.pl
