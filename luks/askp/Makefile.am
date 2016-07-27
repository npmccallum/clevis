EXTRA_DIST = module-setup.sh.in clevis-luks-askpassd.path.in clevis-luks-askpassd.service.in
CLEANFILES = module-setup.sh clevis-luks-askpassd.path clevis-luks-askpassd.service

clevismoddir = $(dracutmodulesdir)/60clevis

systemdsystemunit_DATA = clevis-luks-askpassd.path clevis-luks-askpassd.service
clevismod_SCRIPTS = module-setup.sh

noinst_LTLIBRARIES = libaskp.la
libaskp_la_SOURCES = question.c question.h iface.c iface.h askp.c askp.h
libaskp_la_LIBADD = ../libluks.la

libexec_PROGRAMS = clevis-luks-askpassd
clevis_luks_askpassd_LDADD = libaskp.la

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
