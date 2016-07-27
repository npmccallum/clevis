if USE_LUKSMETA
#SUBDIRS = . askp

AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@ @cryptsetup_CFLAGS@ @udisks2_CFLAGS@ @luksmeta_CFLAGS@

autostartdir = $(sysconfdir)/xdg/autostart
autostart_DATA =
libexec_PROGRAMS =
EXTRA_DIST =
CLEANFILES =

if USE_UDISKS2
#autostart_DATA += clevis-luks-udisks2.desktop
#libexec_PROGRAMS += clevis-luks-udisks2
#clevis_luks_udisks2_LDADD = @cryptsetup_LIBS@ @luksmeta_LIBS@ @udisks2_LIBS@
#EXTRA_DIST += clevis-luks-udisks2.desktop.in
#CLEANFILES += clevis-luks-udisks2.desktop
endif

install-exec-hook:
	if [ -x $(DESTDIR)$(libexecdir)/clevis-luks-udisks2 ]; then \
	    chmod 4711 $(DESTDIR)$(libexecdir)/clevis-luks-udisks2; \
	fi

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
endif
