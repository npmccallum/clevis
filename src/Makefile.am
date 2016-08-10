SUBDIRS = pins

clevisdir = $(libexecdir)/clevis
dist_clevis_SCRIPTS = encrypt decrypt
bin_SCRIPTS = clevis

EXTRA_DIST = clevis.in clevis-luks-udisks2.desktop.in
CLEANFILES = clevis clevis-luks-udisks2.desktop

if USE_LUKSMETA
if USE_CRYPTSETUP
dist_clevis_SCRIPTS += luks-bind

if USE_UDISKS2
autostartdir = $(sysconfdir)/xdg/autostart
autostart_DATA = clevis-luks-udisks2.desktop

libexec_PROGRAMS = clevis-luks-udisks2
clevis_luks_udisks2_CFLAGS = @cryptsetup_CFLAGS@ @luksmeta_CFLAGS@ @udisks2_CFLAGS@
clevis_luks_udisks2_LDADD = @cryptsetup_LIBS@ @luksmeta_LIBS@ @udisks2_LIBS@

install-exec-hook:
	if [ -x $(DESTDIR)$(libexecdir)/clevis-luks-udisks2 ]; then \
	    chmod 4711 $(DESTDIR)$(libexecdir)/clevis-luks-udisks2; \
	fi
endif
endif
endif

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@clevisdir\@,$(clevisdir),g' \
		$(srcdir)/$@.in > $@
