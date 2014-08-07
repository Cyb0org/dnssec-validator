
#ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4


TARGETS = $(EMPTY)
WORKDIRS = $(EMPTY)
BUILT_SOURCES = $(EMPTY)
CLEANFILES = $(EMPTY)


EXTRA_DIST = \
	Makefile.mozz \
	Makefile.cr_dnssec \
	Makefile.cr_tlsa


# FIXME: All architectures do not use the .so suffix.
do_subst = sed \
	-e 's,[@]PACKAGE[@],$(PACKAGE),g' \
	-e 's,[@]OS_TARGET[@],$(OS_TARGET),g' \
	-e 's,[@]VERSION[@],$(VERSION),g'\
	-e 's,[@]libDNSSECcore[@],libDNSSECcore-$(OS_TARGET)-$(XPCOM_ABI).so,g' \
	-e 's,[@]libDANEcore[@],libDANEcore-$(OS_TARGET)-$(XPCOM_ABI).so,g'


include Makefile.mozz
include Makefile.cr_dnssec
include Makefile.cr_tlsa


clean-local:
	for d in $(WORKDIRS); do \
		rm -rf $$d; \
	done


all: $(TARGETS)
