ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src cmd

TESTS = tests/pin-test tests/pin-http tests/pin-sss

bin_SCRIPTS = clevis
EXTRA_DIST = clevis.in
CLEANFILES = clevis

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		$(srcdir)/$@.in > $@

