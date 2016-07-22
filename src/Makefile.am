AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@ @curl_CFLAGS@
LIBS = @jose_LIBS@

#bin_PROGRAMS = clevis

pindir = @CLEVIS_PINDIR@
pin_PROGRAMS = sss http

sss_SOURCES = sss_alg.c sss_alg.h sss.c
http_LDADD = @curl_LIBS@
