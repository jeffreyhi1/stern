INCLUDES = -I$(top_srcdir)/include

TESTS = check-libstern
check_PROGRAMS = check-libstern

check_libstern_SOURCES = check-libstern.c check-libstern-parser.c
check_libstern_LDADD = @CHECK_LIBS@ -L$(top_builddir)/libstern -lstern
check_libstern_CFLAGS = @CHECK_CFLAGS@

