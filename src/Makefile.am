bin_PROGRAMS = sternd
lib_LTLIBRARIES = libstern.la

libstern_la_SOURCES = parse.c stun.c turn.c
libstern_la_LDFLAGS = -version-info 0:0:0

sternd_SOURCES = sternd.c stun_server_tcp.c stun_server_udp.c turn_server.c
sternd_LDADD = libstern.la
