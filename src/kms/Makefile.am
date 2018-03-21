nodist_systemdsystemunit_DATA = clevis-kms@.service clevis-kms@.socket
nodist_bin_SCRIPTS = clevis-kms-add

CLEANFILES=clevis-kms@.service clevis-kms@.socket clevis-kms-add
EXTRA_DIST=clevis-kms@.service.in clevis-kms@.socket.in clevis-kms-add.in

%: %.in
	$(AM_V_GEN)mkdir -p $(dir $@)
	$(AM_V_GEN)$(SED) \
		-e 's,@localstatedir\@,$(localstatedir),g' \
		-e 's,@runstatedir\@,$(runstatedir),g' \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		-e 's,@bindir\@,$(bindir),g' \
		$(srcdir)/$@.in > $@