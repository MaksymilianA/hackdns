CC=clang++

build:
	$(CC) -o hackdns main.c -std=c++11 -g -fstack-protector-all -lresolv -lpthread -Wno-deprecated

