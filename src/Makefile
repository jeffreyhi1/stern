CC=gcc
CFLAGS=-g -ggdb -O0 -Wall
LDFLAGS=-levent -lz -lssl

all: sternd sternd-test libstern.a libstern.so whatsmyip turncat

include .deps

sternd: sternd.o parse.o stun.o stun_server_tcp.o stun_server_udp.o turn_server.o

sternd-test: sternd-test.o stun-tests.o parse.o stun.o turn.o

whatsmyip: whatsmyip.o libstern.so
	gcc -L. -lz -lssl -lstern -o $@ $<

turncat: turncat.o libstern.so
	gcc -L. -lz -lssl -lstern -o $@ $<

libstern.a: parse.o stun.o turn.o
	ar rv $@ $^

libstern.so: parse.o stun.o turn.o
	ld -shared -fPIC -Bdynamic -o $@ $^
	chcon -t textrel_shlib_t $@

clean:
	rm -f *.o sternd sternd-test libstern.a libstern.so

.deps: *.c *.h
	gcc -M *.c > $@
