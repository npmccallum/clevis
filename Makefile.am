ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@
LIBS = @jose_LIBS@

bin_PROGRAMS = clevis-pin-sss clevis-pin-http clevis-pin-tang
check_PROGRAMS = clevis-pin-test
TESTS = \
    tests/clevis-pin-test \
    tests/clevis-pin-sss \
    tests/clevis-pin-http

clevis_pin_sss_SOURCES = pins/clevis-pin-sss.c pins/sss.c pins/sss.h

clevis_pin_http_SOURCES = pins/clevis-pin-http.c pins/http.c pins/http.h
clevis_pin_http_LDADD = -lhttp_parser $(LIBS)

clevis_pin_tang_SOURCES = pins/clevis-pin-tang.c pins/http.c pins/http.h pins/tang.c pins/tang.h
clevis_pin_tang_LDADD = -lhttp_parser $(LIBS)

clevis_pin_test_SOURCES = pins/clevis-pin-test.c
