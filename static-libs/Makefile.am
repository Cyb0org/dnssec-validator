
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4

if STATIC_CORE

all: libs-built/unbound

libs-archives:
	git clone https://gitlab.labs.nic.cz/mstraka/dnssec-libs.git $@

libs-srcs: libs-archives
	$(INSTALL) -d x$@
	cd x$@; tar -xzf ../$</openssl.tar.gz; mv openssl-* openssl; cd ..
	cd x$@; tar -xzf ../$</ldns.tar.gz; mv ldns-* ldns; cd ..
	cd x$@; tar -xzf ../$</unbound.tar.gz; mv unbound-* unbound; cd ..
	mv x$@ $@

libs-built:
	$(INSTALL) -d x$@
	mv x$@ $@

libs-built/openssl: libs-srcs
	$(INSTALL) -d $@
	(cd $</openssl && $(SED) -e 's/\(^"BSD-[^"]*",[^g]*\)gcc\(.*\$\)/\1cc\2/g' < Configure > ConfigureBSD || cp Configure ConfigureBSD; chmod +x ConfigureBSD)
	(cd $</openssl && ./ConfigureBSD no-shared no-krb5 --prefix="$(abs_builddir)/$@" $(OPENSSL_ARGS) $(CROSSCOMPILE_OPENSSL_FLAGS) && $(MAKE) -j1 && $(MAKE) -j1 install && $(MAKE) clean)

libs-built/ldns: libs-srcs libs-built/openssl
	$(INSTALL) -d $@
	(cd $</ldns && $(CROSSCOMPILE_PREPARATION_EXPORTS) \
	    CFLAGS="$(LIB_CFLAGS)" ./configure --disable-shared $(CROSSCOMPILE_HOST_FLAGS) \
	    --with-ssl="$(abs_builddir)/libs-built/openssl" \
	    --disable-ldns-config --without-pyldnsx \
	    --with-pic --prefix="$(abs_builddir)/$@" $(CONFIGURE_ARGS) && \
	    CFLAGS="$(CFLAGS)" $(MAKE) && $(MAKE) install && \
	    $(MAKE) clean)

libs-built/unbound: libs-srcs libs-built/openssl libs-built/ldns
	$(INSTALL) -d $@
	(cd $</unbound && $(CROSSCOMPILE_PREPARATION_EXPORTS) \
	    CFLAGS="$(LIB_CFLAGS)" ./configure --disable-shared $(CROSSCOMPILE_HOST_FLAGS) \
	    --with-ssl="$(abs_builddir)/libs-built/openssl" \
	    --with-ldns="$(abs_builddir)/libs-built/ldns" --without-libevent \
	    --with-pic --prefix="$(abs_builddir)/$@" $(CONFIGURE_ARGS) \
	    --with-libunbound-only && \
	    CFLAGS="$(CFLAGS)" $(MAKE) && $(MAKE) install && \
	    $(MAKE) clean)

#CLEANFILES = \
#	

clean-local:
	-rm -rf libs-srcs libs-built

distclean-local:
	-rm -rf libs-archives

endif
