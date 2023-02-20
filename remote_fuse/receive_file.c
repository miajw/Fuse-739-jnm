#include <stdio.h>
#include <unistd.h>

#include "remote_fuse.h"

int debug_flag = 1;

int main(int argc, char** argv) {
    rpc_init(NULL);

    size_t size;
    int fd = open("output", O_CREAT | O_WRONLY);
    rpc_receive_file("activity", fd, &size);
    close(fd);

    printf("size = %lu\n", size);

}