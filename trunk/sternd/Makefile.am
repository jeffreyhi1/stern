bin_PROGRAMS = sternd
noinst_HEADERS = sternd.h
INCLUDES = -I$(top_srcdir)/include
LDADD = -L$(top_builddir)/libstern -lstern

sternd_SOURCES = sternd.c stun_server_tcp.c stun_server_udp.c turn_server.c $(top_srcdir)/src/util.c
