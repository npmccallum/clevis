AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@ @curl_CFLAGS@
LIBS = @jose_LIBS@

bin_PROGRAMS = clevis-pin-sss clevis-pin-http
check_PROGRAMS = clevis-pin-test

clevis_pin_sss_SOURCES = clevis-pin-sss.c sss.c

clevis_pin_http_SOURCES = clevis-pin-http.c http.c
clevis_pin_http_LDADD = -lhttp_parser $(LIBS)
