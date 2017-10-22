
#AUTOMAKE_OPTIONS = subdir-objects
@CODE_COVERAGE_RULES@

AM_CPPFLAGS = \
	$(CPPFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/util \
	-I$(top_srcdir)/third_party \
	$(MISSING_CPPFLAGS) \
	$(NULL)

lib_LTLIBRARIES = libmsecret.la

AM_LIBS = $(CODE_COVERAGE_LDFLAGS)
AM_CFLAGS = $(CFLAGS) $(CODE_COVERAGE_CFLAGS)

#pkgconfigdir = ${prefix}/lib/pkgconfig
#pkgconfig_DATA = libmsecret.pc

libmsecret_la_SOURCES = \
	msecret.c \
	lkdf.c \
	$(top_srcdir)/third_party/hmac_sha/hmac_sha256.c \
	$(top_srcdir)/third_party/hmac_sha/sha2.c \
	$(NULL)

pkginclude_HEADERS = \
	msecret.h \
	lkdf.h \
	$(NULL)

libmsecret_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES)
libmsecret_la_LDFLAGS = $(AM_LDFLAGS) $(OPENSSL_LDFLAGS)
libmsecret_la_LIBADD = $(AM_LIBADD) $(OPENSSL_LIBS)

DISTCLEANFILES = .deps Makefile

