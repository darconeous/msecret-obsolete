AM_CPPFLAGS = \
	$(CPPFLAGS) \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/util \
	-I$(top_srcdir)/third_party \
	$(MISSING_CPPFLAGS) \
	$(NULL)

@CODE_COVERAGE_RULES@

DISTCLEANFILES = \
	.deps \
	Makefile \
	$(NULL)

bin_PROGRAMS = msecret

msecret_SOURCES = \
	main.c \
	$(top_srcdir)/third_party/base32/base32.c \
	$(top_srcdir)/third_party/base58/base58.c \
	$(top_srcdir)/src/util/help.h \
	$(NULL)

msecret_CPPFLAGS = $(AM_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS) $(OPENSSL_INCLUDES)
msecret_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS) $(OPENSSL_CFLAGS)
msecret_LDADD = $(AM_LDADD) $(CODE_COVERAGE_LIBS) ../libmsecret/libmsecret.la $(OPENSSL_LIBS)
msecret_SOURCES += $(top_builddir)/$(subdir)/version.c

SOURCE_VERSION=$(shell                                            \
	git describe --dirty --always --match "[0-9].*" 2> /dev/null  \
)

BUILT_SOURCES  = $(top_builddir)/$(subdir)/version.c
CLEANFILES     = $(top_builddir)/$(subdir)/version.c
.INTERMEDIATE:   msecret-version.$(OBJEXT)

$(top_builddir)/$(subdir)/version.c: ../version.c.in Makefile
	sed 's/SOURCE_VERSION/"$(SOURCE_VERSION)"/' < $< > $@

