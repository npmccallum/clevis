AC_PREREQ(2.59)
AC_INIT(clevis, 1)
AC_CONFIG_MACRO_DIRS([m4])
AC_CANONICAL_SYSTEM
AC_PROG_CC_C99

AM_INIT_AUTOMAKE([subdir-objects foreign no-dist-gzip dist-bzip2 parallel-tests])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

LT_INIT([disable-static])

PKG_PROG_PKG_CONFIG([0.25])

PKG_CHECK_MODULES([jose], [jose-openssl])

PKG_CHECK_MODULES([dracut], [dracut],
                  [AC_SUBST([dracutmodulesdir], [$($PKG_CONFIG --variable=dracutmodulesdir dracut)])],
                  [AC_SUBST([dracutmodulesdir], [${prefix}/lib/dracut/modules.d])])

PKG_CHECK_MODULES([systemd], [systemd],
		  [AC_SUBST([systemdsystemunitdir], [$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])],
		  [AC_SUBST([systemdsystemunitdir], [${prefix}/lib/systemd/system])])

AC_ARG_WITH(
    [cryptsetup],
    [AS_HELP_STRING([--with-cryptsetup], [build LUKS utilities @<:@default=check@:>@])],
    [],
    [with_cryptsetup=check]
)
AS_CASE(
    ["$with_cryptsetup"],
    [yes], [PKG_CHECK_MODULES([cryptsetup], [libcryptsetup], [HAVE_CRYPTSETUP=1])],
    [no], [HAVE_CRYPTSETUP=0],
    [PKG_CHECK_MODULES([cryptsetup], [libcryptsetup], [HAVE_CRYPTSETUP=1], [HAVE_CRYPTSETUP=0])]
)
AM_CONDITIONAL([USE_CRYPTSETUP], [test "$with_cryptsetup" != no -a "$HAVE_CRYPTSETUP" -eq 1])


AC_ARG_WITH(
    [udisks2],
    [AS_HELP_STRING([--with-udisks2], [build udisks2 unlocker @<:@default=check@:>@])],
    [],
    [with_udisks2=check]
)
AS_CASE(
    ["$with_udisks2"],
    [yes], [PKG_CHECK_MODULES([udisks2], [udisks2], [HAVE_UDISKS2=1])],
    [no], [HAVE_UDISKS2=0],
    [PKG_CHECK_MODULES([udisks2], [udisks2], [HAVE_UDISKS2=1], [HAVE_UDISKS2=0])]
)
AM_CONDITIONAL([USE_UDISKS2], [test "$with_udisks2" != no -a "$HAVE_UDISKS2" -eq 1])


AC_ARG_WITH(
    [luksmeta],
    [AS_HELP_STRING([--with-luksmeta], [build LUKS support @<:@default=check@:>@])],
    [],
    [with_luksmeta=check]
)
AS_CASE(
    ["$with_luksmeta"],
    [yes], [PKG_CHECK_MODULES([luksmeta], [luksmeta], [HAVE_LUKSMETA=1])],
    [no], [HAVE_LUKSMETA=0],
    [PKG_CHECK_MODULES([luksmeta], [luksmeta], [HAVE_LUKSMETA=1], [HAVE_LUKSMETA=0])]
)
AM_CONDITIONAL([USE_LUKSMETA], [test "$with_luksmeta" != no -a "$HAVE_LUKSMETA" -eq 1])


AC_CHECK_HEADER([http_parser.h], [], [AC_MSG_ERROR([http-parser required!])])
AC_SEARCH_LIBS([http_parser_execute], [http_parser], [], [AC_MSG_ERROR([http-parser required!])])

CLEVIS_CFLAGS="\
-Wall \
-Wextra \
-Werror \
-Wstrict-aliasing \
-Wchar-subscripts \
-Wformat-security \
-Wmissing-declarations \
-Wmissing-prototypes \
-Wnested-externs \
-Wpointer-arith \
-Wshadow \
-Wsign-compare \
-Wstrict-prototypes \
-Wtype-limits \
-Wno-missing-field-initializers \
-Wno-unused-parameter \
"
AC_SUBST([CLEVIS_CFLAGS])

AC_SUBST([CLEVIS_PINDIR], [${libdir}/${PACKAGE_NAME}/pins])
AX_DEFINE_DIR(CLEVIS_PINDIR, CLEVIS_PINDIR, [Location of pins (plugins)])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
