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

bin_PROGRAMS = ecollect

ecollect_SOURCES = \
	ecollect.c \
	$(top_srcdir)/third_party/hmac_sha/hmac_sha256.c \
	$(top_srcdir)/third_party/hmac_sha/sha2.c \
	$(NULL)
ecollect_CPPFLAGS = $(AM_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS)
ecollect_CXXFLAGS = $(AM_CXXFLAGS) $(CODE_COVERAGE_CXXFLAGS)
ecollect_CFLAGS = $(AM_CFLAGS) $(CODE_COVERAGE_CFLAGS)
ecollect_LDADD = $(AM_LDADD) $(CODE_COVERAGE_LIBS)
ecollect_SOURCES += $(top_builddir)/$(subdir)/version.c

SOURCE_VERSION=$(shell                                            \
	git describe --dirty --always --match "[0-9].*" 2> /dev/null  \
)

BUILT_SOURCES  = $(top_builddir)/$(subdir)/version.c
CLEANFILES     = $(top_builddir)/$(subdir)/version.c
.INTERMEDIATE:   ecollect-version.$(OBJEXT)

$(top_builddir)/$(subdir)/version.c: ../version.c.in Makefile
	sed 's/SOURCE_VERSION/"$(SOURCE_VERSION)"/' < $< > $@

