bin_PROGRAMS = sternd
noinst_LTLIBRARIES = libsternd.la
noinst_HEADERS = sternd.h
INCLUDES = -I$(top_srcdir)/include

libsternd_la_SOURCES = stun_server.c \
					   turn_server.c \
					   sternd.c \
					   ../src/util.c \
					   ../src/buffer.c

sternd_SOURCES = main.c
sternd_LDADD = libsternd.la ../libstern/libstern.la
