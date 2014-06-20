REPO=`basename \`git config --get remote.origin.url\``
VERSION_FULL=$(REPO)-`cat VERSION`
VERSION_MIN=$(REPO)-`cat VERSION`-minimal
HAVE_MODULES=git submodule | grep -v cmake >/dev/null

all:

dist:
	@rm -rf $(VERSION_FULL) $(VERSION_FULL).tgz
	@rm -rf $(VERSION_MIN) $(VERSION_MIN).tgz
	@mkdir $(VERSION_FULL)
	@tar --exclude=$(VERSION_FULL)* --exclude=$(VERSION_MIN)* --exclude=.git -cf - . | ( cd $(VERSION_FULL) && tar -xpf - )
	@( cd $(VERSION_FULL) && cp -R ../.git . && git reset -q --hard HEAD && git clean -xdfq && rm -rf .git )
	@tar -czf $(VERSION_FULL).tgz $(VERSION_FULL) && echo Package: $(VERSION_FULL).tgz && rm -rf $(VERSION_FULL)
	@$(HAVE_MODULES) && mkdir $(VERSION_MIN) || exit 0
	@$(HAVE_MODULES) && tar --exclude=$(VERSION_FULL)* --exclude=$(VERSION_MIN)* --exclude=.git `git submodule | awk '{print "--exclude="$$2}' | grep -v cmake | tr '\n' ' '` -cf - . | ( cd $(VERSION_MIN) && tar -xpf - ) || exit 0
	@$(HAVE_MODULES) && ( cd $(VERSION_MIN) && cp -R ../.git . && git reset -q --hard HEAD && git clean -xdfq && rm -rf .git ) || exit 0
	@$(HAVE_MODULES) && tar -czf $(VERSION_MIN).tgz $(VERSION_MIN) && echo Package: $(VERSION_MIN).tgz && rm -rf $(VERSION_MIN) || exit 0

distclean:
	rm -rf build/
