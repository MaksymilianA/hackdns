CC=clang

build:
	$(CC) -o bin/hackdns main.c -fstack-protector-all -lresolv -lpthread

