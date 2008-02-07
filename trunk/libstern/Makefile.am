lib_LTLIBRARIES = libstern.la
noinst_HEADERS = libstern.h
INCLUDES = -I$(top_srcdir)/include

libstern_la_SOURCES = parse.c \
					  stun.c \
					  turn.c \
					  ../src/util.c \
					  ../src/buffer.c
libstern_la_LDFLAGS = -version-info 0:0:0
