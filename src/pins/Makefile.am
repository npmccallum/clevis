AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@ @luksmeta_CFLAGS@ @cryptsetup_CFLAGS@ @udisks2_CFLAGS@

pinsdir = $(libexecdir)/clevis/pins

pins_PROGRAMS = sss http tang
check_PROGRAMS = test

sss_SOURCES = sss.c libsss.c libsss.h
sss_LDADD = @jose_LIBS@

http_SOURCES = http.c libhttp.c libhttp.h
http_LDADD = @jose_LIBS@ -lhttp_parser

tang_SOURCES = tang.c libhttp.c libhttp.h libtang.c libtang.h
tang_LDADD = @jose_LIBS@ -lhttp_parser

test_SOURCES = test.c
test_LDADD = @jose_LIBS@
