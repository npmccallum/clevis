ACLOCAL_AMFLAGS = -I m4
AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@ @luksmeta_CFLAGS@ @cryptsetup_CFLAGS@ @udisks2_CFLAGS@

bin_PROGRAMS = clevis-pin-sss clevis-pin-http clevis-pin-tang clevis-encrypt clevis-decrypt
check_PROGRAMS = clevis-pin-test
TESTS = \
    tests/clevis-pin-test \
    tests/clevis-pin-sss \
    tests/clevis-pin-http

clevis_pin_sss_SOURCES = pins/clevis-pin-sss.c pins/sss.c pins/sss.h
clevis_pin_sss_LDADD = @jose_LIBS@

clevis_pin_http_SOURCES = pins/clevis-pin-http.c pins/http.c pins/http.h
clevis_pin_http_LDADD = @jose_LIBS@ -lhttp_parser

clevis_pin_tang_SOURCES = pins/clevis-pin-tang.c pins/http.c pins/http.h pins/tang.c pins/tang.h
clevis_pin_tang_LDADD = @jose_LIBS@ -lhttp_parser

clevis_pin_test_SOURCES = pins/clevis-pin-test.c
clevis_pin_test_LDADD = @jose_LIBS@

if USE_LUKSMETA
if USE_CRYPTSETUP
dist_bin_SCRIPTS = clevis-luks-bind

if USE_UDISKS2
autostartdir = $(sysconfdir)/xdg/autostart
autostart_DATA = luks/clevis-luks-udisks2.desktop
libexec_PROGRAMS = clevis-luks-udisks2
clevis_luks_udisks2_SOURCES = luks/clevis-luks-udisks2.c
clevis_luks_udisks2_LDADD = @cryptsetup_LIBS@ @luksmeta_LIBS@ @udisks2_LIBS@
EXTRA_DIST = luks/clevis-luks-udisks2.desktop.in
CLEANFILES = luks/clevis-luks-udisks2.desktop

install-exec-hook:
	if [ -x $(DESTDIR)$(libexecdir)/clevis-luks-udisks2 ]; then \
	    chmod 4711 $(DESTDIR)$(libexecdir)/clevis-luks-udisks2; \
	fi

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@
endif
endif
endif
