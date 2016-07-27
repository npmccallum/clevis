ACLOCAL_AMFLAGS = -I m4
SUBDIRS = . luks

AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@

bin_PROGRAMS = clevis-pin-sss clevis-pin-http clevis-pin-tang
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
bin_PROGRAMS += clevis-luks-bind
clevis_luks_bind_CFLAGS = $(AM_CFLAGS) @cryptsetup_CFLAGS@ @luksmeta_CFLAGS@ @zlib_CFLAGS@
clevis_luks_bind_SOURCES = luks/clevis-luks-bind.c luks/pcmd.c luks/pcmd.h luks/luks.c luks/luks.h
clevis_luks_bind_LDADD = @cryptsetup_LIBS@ @luksmeta_LIBS@ @jose_LIBS@ @zlib_CFLAGS@
endif
endif
