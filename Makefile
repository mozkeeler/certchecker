CC=clang
CFLAGS=-Wall -g -O0 -std=gnu99 -I/usr/include/nss -I/usr/include/nspr
LDFLAGS=-lnss3 -lnspr4 -lsmime3 -lnssutil3 -lplc4

certchecker: certchecker.o nss_private.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f certchecker.o nss_private.o certchecker
