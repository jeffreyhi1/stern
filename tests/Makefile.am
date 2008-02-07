INCLUDES = -I$(top_srcdir)/include

TESTS = check-libstern check-sternd
check_PROGRAMS = check-libstern check-libstern-coverage check-sternd check-sternd-coverage

check_libstern_SOURCES = check-libstern.c \
						 check-libstern-parser.c \
						 check-libstern-stun.c \
						 check-libstern-turn.c
check_libstern_LDADD = @CHECK_LIBS@ \
					   ../libstern/libstern.la
check_libstern_CFLAGS = @CHECK_CFLAGS@

check_libstern_coverage_SOURCES = $(check_libstern_SOURCES) \
								  ../libstern/parse.c \
								  ../libstern/stun.c \
								  ../libstern/turn.c \
								  ../src/util.c
check_libstern_coverage_LDADD = @CHECK_LIBS@
check_libstern_coverage_CFLAGS = @CHECK_CFLAGS@ -g -Wall -fprofile-arcs -ftest-coverage

check_sternd_SOURCES = check-sternd.c \
					   check-sternd-stund.c
check_sternd_LDADD = @CHECK_LIBS@ \
					 ../sternd/libsternd.la \
					 ../libstern/libstern.la
check_sternd_CFLAGS = @CHECK_CFLAGS@

check_sternd_coverage_SOURCES = $(check_sternd_SOURCES) \
								../sternd/stun_server_tcp.c \
								../sternd/stun_server_udp.c \
								../sternd/turn_server.c \
								../src/util.c
check_sternd_coverage_LDADD = @CHECK_LIBS@ \
							  ../libstern/libstern.la
check_sternd_coverage_CFLAGS = @CHECK_CFLAGS@ -g -Wall -fprofile-arcs -ftest-coverage

clean-local:
	rm -f *.gcda *.gcno
