#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])

dnl This is the project name and release verison number.
dnl The release version is stored in the file `.default-version`.
dnl Update that file *after* every release to indicate the version
dnl of the *next* anticipated release.
AC_INIT(
	[msecret],
	m4_esyscmd([printf "%s" `cat .default-version`]),
	[],
	[msecret],
	[https://github.com/darconeous/msecret/]dnl
)

AC_CONFIG_SRCDIR([src/libmsecret/msecret.h])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIRS([m4])

AM_INIT_AUTOMAKE()

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

m4_ifdef([AX_CODE_COVERAGE], [AX_CODE_COVERAGE], [AC_SUBST([CODE_COVERAGE_RULES])])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL
LT_INIT

# Checks for libraries.
AX_CHECK_OPENSSL

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h stddef.h stdint.h stdlib.h string.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memmove memset strchr strerror strtol])

AC_CONFIG_FILES([Makefile src/Makefile doc/Makefile src/ecollect/Makefile third_party/Makefile src/libmsecret/Makefile src/libmsecret/libmsecret.pc src/msecret/Makefile])
AC_OUTPUT
