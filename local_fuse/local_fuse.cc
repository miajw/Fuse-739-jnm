
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/xattr.h>

#define _XOPEN_SOURCE 700
#define ERRNO_NOOP -999

#include "fuse.h"

extern int debug_flag;


extern "C" int rpc_lstat(const char *path, struct stat *buf)
{
    memset(buf, 0, sizeof(struct stat));
    if (lstat(path, buf) == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_getattr(const char *path, struct stat *buf)
{
    memset(buf, 0, sizeof(struct stat));
    if (lstat(path, buf) == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_readlink(const char *path, char *buf, size_t bufsiz)
{
    int ret = readlink(path, buf, bufsiz);
    if (ret == -1) {
        return -errno;
    }
    buf[ret] = 0;

    return 0;
}

extern "C" int rpc_mknod(const char *path, mode_t mode, dev_t dev)
{
    int ret = mknod(path, mode, dev);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_mkdir(const char *path, mode_t mode)
{
    int ret = mkdir(path, mode);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_unlink(const char *path)
{
    int ret = unlink(path);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_rmdir(const char *path) {
    int ret = rmdir(path);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_symlink(const char *target, const char *linkpath)
{
    int ret = symlink(target, linkpath);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_rename(const char *oldpath, const char *newpath)
{
    int ret = rename(oldpath, newpath);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_link(const char *oldpath, const char *newpath)
{
    int ret = link(oldpath, newpath);
    if (ret < 0) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_chmod(const char *path, mode_t mode)
{
    int ret = chmod(path, mode);
    if (ret < 0) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_chown(const char *path, uid_t owner, gid_t group)
{
    int ret = chown(path, owner, group);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_truncate(const char *path, off_t length)
{
    int ret = truncate(path, length);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_open(const char *path, struct fuse_file_info *fi)
{
    if(fi == NULL) return -EINVAL;

    int ret = open(path, fi->flags);
    if (ret == -1) return -errno;

    fi->fh = ret;

    return 0;
}

extern "C" int rpc_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
    if(fi == NULL) return -EINVAL;

    int ret = pread(fi->fh, buffer, size, offset);
    if (ret == -1) return -errno;

    return ret;
}

extern "C" int rpc_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    if(fi == NULL) return -EINVAL;

    int ret = pwrite(fi->fh, buf, size, offset);
    if (ret == -1) return -errno;
    return ret;
}

extern "C" int rpc_statfs(const char *path, struct statvfs *buf) {
    int ret = statvfs(path, buf);
    if (ret == -1) return -errno;
    return 0;
}

extern "C" int rpc_flush(const char *path, struct fuse_file_info *fi) {
    if(fi == NULL) return -EINVAL;

    int ret = close(dup(fi->fh));
    if (ret == -1) return -errno;

    return 0;
}

extern "C" int rpc_release(const char *path, struct fuse_file_info *fi)
{
    int ret = close(fi->fh);
    if (ret == -1) return -errno;

    return 0;
}

extern "C" int rpc_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
    if(fi == NULL) return -EINVAL;

    if (datasync) {
        int ret = fdatasync(fi->fh);
        if (ret == -1) return -errno;

    } else {
        int ret = fsync(fi->fh);
        if (ret == -1) return -errno;
    }

    return 0;
}

extern "C" int rpc_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{
    int ret = setxattr(path, name, value, size, flags);

    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_getxattr(const char *path, const char *name, char *value, size_t size)
{
    int ret = getxattr(path, name, value, size);
    if (ret == -1) {
        printf("getxattr returned error path:[%s] errno:%d -- %s\n", path, errno, strerror(errno));
        return -errno;
    }

    printf("getxattr path:[%s] name:[%s] value:[%s] size:%lu\n", path, name, value, size);

    return 0;
}

extern "C" int rpc_listxattr(const char *path, char *list, size_t size)
{
    int ret = listxattr(path, list, size);
    if (ret == -1) {
        return -errno;
    }

    return ret;
}

extern "C" int rpc_removexattr(const char *path, const char *name)
{
    int ret = removexattr(path, name);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_opendir(const char *path, struct fuse_file_info *fi)
{
    DIR *dir = opendir(path);

    if (!dir) {
        return -errno;
    }
    fi->fh = (int64_t) dir;

    return 0;
}

extern "C" int rpc_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    DIR *dp = opendir(path);
    if (dp == NULL) {
        return -errno;
    }
    struct dirent *de;

    (void) offset;
    (void) fi;

    while ((de = readdir(dp)) != NULL) {
//        struct stat st;
//        memset(&st, 0, sizeof(st));
//        st.st_ino = de->d_ino;
//        st.st_mode = de->d_type << 12;
//        if (filler(buf, de->d_name, &st, 0))
        if (filler(buf, de->d_name, NULL, 0))
            break;
    }
    closedir(dp);

    return 0;
}

extern "C" int rpc_releasedir(const char *path, struct fuse_file_info *fi)
{
    DIR *dir = (DIR *) fi->fh;

    int ret = closedir(dir);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    int ret;

    DIR *dir = opendir(path);
    if (!dir) {
        return -errno;
    }

    if (datasync) {
        ret = fdatasync(dirfd(dir));
        if (ret == -1) {
            return -errno;
        }
    } else {
        ret = fsync(dirfd(dir));
        if (ret == -1) {
            return -errno;
        }
    }
    closedir(dir);

    return 0;
}

extern "C" void *rpc_init(struct fuse_conn_info *conn)
{
    return NULL;
}

extern "C" void rpc_destroy(void *private_data)
{

}

extern "C" int rpc_access(const char *path, int mode)
{
    int ret = access(path, mode);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    int ret = open(path, fi->flags, mode);
    if (ret == -1) {
        return -errno;
    }
    fi->fh = ret;

    return 0;
}

extern "C" int rpc_ftruncate(const char *path, off_t length, struct fuse_file_info *fi)
{
    int ret = truncate(path, length);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_fgetattr(const char *path, struct stat *buf, struct fuse_file_info *fi)
{
    int ret = fstat((int) fi->fh, buf);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_lock(const char *path, struct fuse_file_info *fi, int cmd, struct flock *fl)
{
    int ret = fcntl((int) fi->fh, cmd, fl);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_ioctl(const char *path, int cmd, void *arg, struct fuse_file_info *fi, unsigned int flags, void *data)
{
    int ret = ioctl(fi->fh, cmd, arg);
    if (ret == -1) {
        return -errno;
    }

    return ret;
}

extern "C" int rpc_flock(const char *path, struct fuse_file_info *fi, int op)
{
    int ret = flock(((int) fi->fh), op);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_fallocate(const char *path, int mode, off_t offset, off_t len, struct fuse_file_info *fi)
{
    int fd;
    (void) fi;

    if (mode) {
	return -EOPNOTSUPP;
    }

    if(fi == NULL) {
	fd = open(path, O_WRONLY);
    } else {
	fd = fi->fh;
    }

    if (fd == -1) {
	return -errno;
    }

    int ret = fallocate((int) fi->fh, mode, offset, len);
    if (ret == -1) {
        return -errno;
    }

    if(fi == NULL) {
	close(fd);
    }

    return 0;
}

extern "C" int rpc_utimens(const char *path, const struct timespec ts[2])
{
    /* don't use utime/utimes since they follow symlinks */
    int ret = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

