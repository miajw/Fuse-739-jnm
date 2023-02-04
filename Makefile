CCFLAGS = -Wall -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse -lfuse -pthread

all: fuse_server

fuse_server: fuse_server.c
	gcc fuse_server.c -o fuse_server $(CCFLAGS)
