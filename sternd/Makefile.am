bin_PROGRAMS = sternd
noinst_LTLIBRARIES = libsternd.la
noinst_HEADERS = sternd.h
INCLUDES = -I$(top_srcdir)/include

libsternd_la_SOURCES = stun_server.c \
					   turn_server.c \
					   ../src/util.c

sternd_SOURCES = sternd.c
sternd_LDADD = libsternd.la ../libstern/libstern.la
