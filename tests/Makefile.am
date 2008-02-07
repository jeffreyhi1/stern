INCLUDES = -I$(top_srcdir)/include
LIBS += @CHECK_LIBS@
AM_CFLAGS = @CHECK_CFLAGS@
COV_CFLAGS = -g -Wall -fprofile-arcs -ftest-coverage

TESTS = check-libstern check-sternd
check_PROGRAMS = check-libstern check-libstern-coverage check-sternd check-sternd-coverage

check_libstern_SOURCES = check-libstern.c \
						 check-libstern-parser.c \
						 check-libstern-stun.c \
						 check-libstern-turn.c
check_libstern_LDADD = ../libstern/libstern.la

check_libstern_coverage_SOURCES = $(check_libstern_SOURCES) \
								  ../libstern/parse.c \
								  ../libstern/stun.c \
								  ../libstern/turn.c \
								  ../src/util.c \
								  ../src/buffer.c
check_libstern_coverage_CFLAGS = $(COV_CFLAGS)

check_sternd_SOURCES = check-sternd.c \
					   check-sternd-stund.c
check_sternd_LDADD = ../sternd/libsternd.la \
					 ../libstern/libstern.la

check_sternd_coverage_SOURCES = $(check_sternd_SOURCES) \
								../sternd/stun_server.c \
								../sternd/turn_server.c \
								../src/util.c \
								../src/buffer.c
check_sternd_coverage_LDADD = ../libstern/libstern.la
check_sternd_coverage_CFLAGS = $(COV_CFLAGS)

clean-local:
	rm -f *.gcda *.gcno
