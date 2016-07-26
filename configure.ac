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

PKG_CHECK_MODULES([jose], [jose])

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
