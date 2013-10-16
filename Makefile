CC=clang
CFLAGS=-g -O0 -std=gnu99 -I/usr/include/nss -I/usr/include/nspr
LDFLAGS=-lnss3 -lnspr4 -lsmime3 

certchecker: certchecker.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f certchecker.o certchecker
