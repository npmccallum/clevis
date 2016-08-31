AM_CFLAGS = @CLEVIS_CFLAGS@ @jose_CFLAGS@
LDADD = @jose_LIBS@

pinsdir = $(libexecdir)/clevis/pins

pins_PROGRAMS = sss http tang
check_PROGRAMS = test

sss_SOURCES = sss.c libsss.c libsss.h

http_SOURCES = http.c libhttp.c libhttp.h
http_LDADD = $(LDADD) -lhttp_parser

tang_SOURCES = tang.c libhttp.c libhttp.h libtang.c libtang.h
tang_LDADD = $(LDADD) -lhttp_parser

test_SOURCES = test.c
