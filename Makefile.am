ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

TESTS = tests/clevis-pin-test tests/clevis-pin-http tests/clevis-pin-sss

#if USE_LUKSMETA
#if USE_CRYPTSETUP
#dist_bin_SCRIPTS = clevis-luks-bind

#if USE_UDISKS2
#autostartdir = $(sysconfdir)/xdg/autostart
#autostart_DATA = luks/clevis-luks-udisks2.desktop
#libexec_PROGRAMS = clevis-luks-udisks2
#clevis_luks_udisks2_SOURCES = luks/clevis-luks-udisks2.c
#clevis_luks_udisks2_LDADD = @cryptsetup_LIBS@ @luksmeta_LIBS@ @udisks2_LIBS@
#EXTRA_DIST = luks/clevis-luks-udisks2.desktop.in
#CLEANFILES = luks/clevis-luks-udisks2.desktop
#
#install-exec-hook:
#	if [ -x $(DESTDIR)$(libexecdir)/clevis-luks-udisks2 ]; then \
#	    chmod 4711 $(DESTDIR)$(libexecdir)/clevis-luks-udisks2; \
#	fi
#
#%: %.in
#	$(AM_V_GEN)$(SED) \
#		-e 's,@libexecdir\@,$(libexecdir),g' \
#		$(srcdir)/$@.in > $@
#endif
#endif
#endif
