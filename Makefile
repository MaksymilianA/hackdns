CC=clang

build:
	$(CC) -o hackdns main.c -fstack-protector-all -lresolv -lpthread

