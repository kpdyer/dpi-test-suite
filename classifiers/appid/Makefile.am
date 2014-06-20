AUTOMAKE_OPTIONS= foreign

include_HEADERS = appid.h

lib_LTLIBRARIES = libappid.la

libappid_la_SOURCES = appid_list.c appid_hexdump.c appid.c

dist: appid_apps-$(VERSION).tar.gz

.PHONY: appid_apps-$(VERSION).tar.gz

appid_apps-$(VERSION).tar.gz:
	tar zcf $@ apps

if HAVE_PYTHON
# XXX - some hackery here
noinst_SCRIPTS = python-build

appid.rl appid.h appid_list.c: appid.h.tmpl appid_list.c.tmpl appid.rl.tmpl
	$(PYTHON) gencode.py

python-build: pyappid.c
	$(PYTHON) setup.py build
	touch python-build

python-clean:
	rm -rf *build

clean: python-clean
	rm -rf *.pyc

distclean: clean

python-install:
	$(PYTHON) setup.py install --prefix=$(DESTDIR)$(prefix)

install-exec-local: python-install
endif

if HAVE_PYREX
pyappid.c: appid.pyx
	pyrexc -o $@ appid.pyx
endif

if HAVE_RAGEL
appid.c: appid.rl
	$(RAGEL) appid.rl | $(RLGEN) -G2 -o $@
endif

genclean: distclean
	rm -f appid.h appid.c appid_list.c appid.rl

# Remove anything that could ever be generated.
mrproper: clean mostlyclean distclean genclean
	rm -f Makefile.in aclocal.m4 config.guess config.sub pyappid.c ltmain.sh
	rm -f configure install-sh missing depcomp mkinstalldirs config.log config.status
	rm -rf autom4te.cache
	rm -f appid_apps-$(VERSION).tar.gz
	rm -f appid-$(VERSION).tar.gz
	rm -rf appid-$(VERSION)
	rm -f Makefile

EXTRA_DIST =	appid.h.tmpl appid.h appid.rl.tmpl appid.rl \
		appid_list.c.tmpl appid.pyx pyappid.c setup.py \
		HACKING LICENSE bootstrap gencode.py stpy.py template

DISTCLEANFILES = *~ apps/*~
