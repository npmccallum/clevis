ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@
LIBS = @jose_LIBS@

bin_PROGRAMS = clevis-pin-sss clevis-pin-http
check_PROGRAMS = clevis-pin-test
TESTS = \
    tests/clevis-pin-test \
    tests/clevis-pin-sss \
    tests/clevis-pin-http

clevis_pin_sss_SOURCES = src/clevis-pin-sss.c src/sss.c src/sss.h

clevis_pin_http_SOURCES = src/clevis-pin-http.c src/http.c src/http.h
clevis_pin_http_LDADD = -lhttp_parser $(LIBS)

clevis_pin_test_SOURCES = src/clevis-pin-test.c
