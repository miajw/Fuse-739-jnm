
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <fcntl.h>

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/xattr.h>
#include <sys/statvfs.h>



int dump_stat(char* path) {
    struct stat buf;
    memset(&buf, 0, sizeof(struct stat));
    if (lstat(path, &buf) == -1) {
        return -errno;
    }

    printf("dev %lu\n", buf.st_dev);
    printf("ino %lu\n", buf.st_ino);
    printf("mode %d\n", buf.st_mode);
    printf("nlink %lu\n", buf.st_nlink);
    printf("uid %d\n", buf.st_uid);
    printf("gid %d\n", buf.st_gid);
    printf("rdev %lu\n", buf.st_rdev);
    printf("size %lu\n", buf.st_size);
//    printf("asec %d\n", buf.st_asec);
//    printf("anano %d\n", buf.st_anano);
//    printf("msec %d\n", buf.st_msec);
//    printf("mnano %d\n", buf.st_mnano);
//    printf("csec %d\n", buf.st_csec);
//    printf("cnano %d\n", buf.st_cnano);
    printf("atim %ld.%09ld\n", buf.st_atim.tv_sec, buf.st_atim.tv_nsec);
    printf("mtim %ld.%09ld\n", buf.st_mtim.tv_sec, buf.st_mtim.tv_nsec);
    printf("ctim %ld.%09ld\n", buf.st_ctim.tv_sec, buf.st_ctim.tv_nsec);
    printf("blksize %ld\n", buf.st_blksize);
    printf("blocks %ld\n", buf.st_blocks);
//    printf("attr %d\n", buf.st_attr);

    return 0;
}

int dump_vfsstat(char* path) {
    struct statvfs buf;
    int ret = statvfs(path, &buf);
    if (ret == -1) exit(-2);

    printf("f_bsize %lu\n", buf.f_bsize);
    printf("f_frsize %lu\n", buf.f_frsize);
    printf("f_blocks %lu\n", buf.f_blocks);
    printf("f_bfree %lu\n", buf.f_bfree);
    printf("f_bavail %lu\n", buf.f_bavail);
    printf("f_files %lu\n", buf.f_files);
    printf("f_ffree %lu\n", buf.f_ffree);
    printf("f_favail %lu\n", buf.f_favail);
    printf("f_fsid %lu\n", buf.f_fsid);
    printf("f_flag %lu\n", buf.f_flag);
    printf("f_namemax %lu\n", buf.f_namemax);
//    printf("attr %d\n", buf.st_attr);

    return 0;
}
//
//struct statvfs {
//    unsigned long  f_bsize;    /* Filesystem block size */
//    unsigned long  f_frsize;   /* Fragment size */
//    fsblkcnt_t     f_blocks;   /* Size of fs in f_frsize units */
//    fsblkcnt_t     f_bfree;    /* Number of free blocks */
//    fsblkcnt_t     f_bavail;   /* Number of free blocks for
//                                             unprivileged users */
//    fsfilcnt_t     f_files;    /* Number of inodes */
//    fsfilcnt_t     f_ffree;    /* Number of free inodes */
//    fsfilcnt_t     f_favail;   /* Number of free inodes for
//                                             unprivileged users */
//    unsigned long  f_fsid;     /* Filesystem ID */
//    unsigned long  f_flag;     /* Mount flags */
//    unsigned long  f_namemax;  /* Maximum filename length */
//};

int main(int argc, char** argv) {
    if(argc<2) {
        printf("usage: %s <path>\n", argv[0]);
        exit(1);
    }

    char* path = argv[1];

    dump_vfsstat(path);

    dump_stat(path);

    struct timespec ts[2];
    clock_gettime(CLOCK_REALTIME, &ts[0]);
    clock_gettime(CLOCK_REALTIME, &ts[1]);

    printf("ts[0] %ld.%09ld\n", ts[0].tv_sec, ts[0].tv_nsec);
    printf("ts[1] %ld.%09ld\n", ts[1].tv_sec, ts[1].tv_nsec);

    int ret = utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
    if (ret == -1) {
        printf("utimensat failed errno:%d\n", errno);
        return -errno;
    }

    dump_stat(path);
}
