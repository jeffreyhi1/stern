INCLUDES = -I$(top_srcdir)/include

TESTS = check-libstern
check_PROGRAMS = check-libstern check-libstern-coverage

check_libstern_SOURCES = check-libstern.c check-libstern-parser.c check-libstern-stun.c check-libstern-turn.c
check_libstern_LDADD = @CHECK_LIBS@ ../libstern/libstern.la
check_libstern_CFLAGS = @CHECK_CFLAGS@


check_libstern_coverage_SOURCES = check-libstern.c check-libstern-parser.c check-libstern-stun.c check-libstern-turn.c \
								  ../libstern/parse.c ../libstern/stun.c ../libstern/turn.c \
								  ../src/util.c
check_libstern_coverage_LDADD = @CHECK_LIBS@
check_libstern_coverage_CFLAGS = @CHECK_CFLAGS@ -g -Wall -fprofile-arcs -ftest-coverage

clean-local:
	rm -f *.gcda *.gcno
