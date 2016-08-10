SUBDIRS = pins

clevisdir = $(libexecdir)/clevis
clevis_SCRIPTS = encrypt decrypt luks-bind
bin_SCRIPTS = clevis
EXTRA_DIST = clevis.in

%: %.in
	$(AM_V_GEN)$(SED) \
		-e 's,@clevisdir\@,$(clevisdir),g' \
		$(srcdir)/$@.in > $@
