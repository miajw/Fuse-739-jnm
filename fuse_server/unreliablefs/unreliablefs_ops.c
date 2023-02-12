#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/file.h>
#ifdef HAVE_XATTR
#include <sys/xattr.h>
#endif /* HAVE_XATTR */

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#define ERRNO_NOOP -999

#include "unreliablefs_ops.h"
#include "remote_fuse.h"

const char *fuse_op_name[] = {
    "getattr",
    "readlink",
    "mknod",
    "mkdir",
    "unlink",
    "rmdir",
    "symlink",
    "rename",
    "link",
    "chmod",
    "chown",
    "truncate",
    "open",
    "read",
    "write",
    "statfs",
    "flush",
    "release",
    "fsync",
#ifdef HAVE_XATTR
    "setxattr",
    "getxattr",
    "listxattr",
    "removexattr",
#endif /* HAVE_XATTR */
    "opendir",
    "readdir",
    "releasedir",
    "fsyncdir",
    "access",
    "creat",
    "ftruncate",
    "fgetattr",
    "lock",
#if !defined(__OpenBSD__)
    "ioctl",
#endif /* __OpenBSD__ */
#ifdef HAVE_FLOCK
    "flock",
#endif /* HAVE_FLOCK */
#ifdef HAVE_FALLOCATE
    "fallocate",
#endif /* HAVE_FALLOCATE */
#ifdef HAVE_UTIMENSAT
    "utimens",
#endif /* HAVE_UTIMENSAT */
    "lstat"
};

extern int error_inject(const char* path, fuse_op operation);

int unreliable_lstat(const char *path, struct stat *buf)
{
    int ret = error_inject(path, OP_LSTAT);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_lstat(path, buf);
 }

int unreliable_getattr(const char *path, struct stat *buf)
{
    int ret = error_inject(path, OP_GETATTR);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_getattr(path, buf);
}

int unreliable_readlink(const char *path, char *buf, size_t bufsiz)
{
    int ret = error_inject(path, OP_READLINK);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_readlink(path, buf, bufsiz);
}

int unreliable_mknod(const char *path, mode_t mode, dev_t dev)
{
    int ret = error_inject(path, OP_MKNOD);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_mknod(path, mode, dev);
}

int unreliable_mkdir(const char *path, mode_t mode)
{
    int ret = error_inject(path, OP_MKDIR);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_mkdir(path, mode);
}

int unreliable_unlink(const char *path)
{
    int ret = error_inject(path, OP_UNLINK);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_unlink(path);
}

int unreliable_rmdir(const char *path) {
    int ret = error_inject(path, OP_RMDIR);
    if (ret == - ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_rmdir(path);
}

int unreliable_symlink(const char *target, const char *linkpath)
{
    int ret = error_inject(target, OP_SYMLINK);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_symlink(target, linkpath);
}

int unreliable_rename(const char *oldpath, const char *newpath)
{
    int ret = error_inject(oldpath, OP_RENAME);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_rename(oldpath, newpath);
}

int unreliable_link(const char *oldpath, const char *newpath)
{
    int ret = error_inject(oldpath, OP_LINK);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_link(oldpath, newpath);
}

int unreliable_chmod(const char *path, mode_t mode)
{
    int ret = error_inject(path, OP_CHMOD);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_chmod(path, mode);
}

int unreliable_chown(const char *path, uid_t owner, gid_t group)
{
    int ret = error_inject(path, OP_CHOWN);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_chown( path, owner, group);
}

int unreliable_truncate(const char *path, off_t length)
{
    int ret = error_inject(path, OP_TRUNCATE);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_truncate(path, length);
 }

int unreliable_open(const char *path, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_OPEN);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_open(path, fi);
}

int unreliable_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_READ);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_read(path, buf, size, offset, fi);
}

int unreliable_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_WRITE);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_write(path, buf, size, offset, fi);
}

int unreliable_statfs(const char *path, struct statvfs *buf)
{
    int ret = error_inject(path, OP_STATFS);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_statfs(path, buf);
}

int unreliable_flush(const char *path, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_FLUSH);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_flush(path, fi);
}

int unreliable_release(const char *path, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_RELEASE);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_release(path, fi);
}

int unreliable_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_FSYNC);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_fsync(path, datasync, fi);
}

int unreliable_setxattr(const char *path, const char *name,
                        const char *value, size_t size, int flags) {
    int ret = error_inject(path, OP_SETXATTR);
    if (ret == - ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }
    return rpc_setxattr(path, name, value, size, flags);
}

int unreliable_getxattr(const char *path, const char *name,
                        char *value, size_t size)
{
    int ret = error_inject(path, OP_GETXATTR);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }
    return rpc_getxattr(path, name, value, size);
}

int unreliable_listxattr(const char *path, char *list, size_t size)
{
    int ret = error_inject(path, OP_LISTXATTR);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_listxattr(path, list, size);
}

int unreliable_removexattr(const char *path, const char *name) {
    int ret = error_inject(path, OP_REMOVEXATTR);
    if (ret == - ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_removexattr(path, name);
}

int unreliable_opendir(const char *path, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_OPENDIR);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_opendir(path, fi);
}

int unreliable_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_READDIR);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_readdir(path, buf, filler, offset, fi);
}

int unreliable_releasedir(const char *path, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_RELEASEDIR);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_releasedir(path, fi);
}

int unreliable_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_FSYNCDIR);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_fsyncdir(path, datasync, fi);
}

void *unreliable_init(struct fuse_conn_info *conn)
{
    return rpc_init(conn);
}

void unreliable_destroy(void *private_data)
{
    rpc_destroy(private_data);
}

int unreliable_access(const char *path, int mode)
{
    int ret = error_inject(path, OP_ACCESS);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_access(path, mode);
 }

int unreliable_create(const char *path, mode_t mode,
                      struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_CREAT);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_create(path, mode, fi);
}

int unreliable_ftruncate(const char *path, off_t length,
                         struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_FTRUNCATE);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_truncate(path, length);
}

int unreliable_fgetattr(const char *path, struct stat *buf, struct fuse_file_info *fi)
{
    int ret = error_inject(path, OP_FGETATTR);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_fgetattr(path, buf, fi);
}

int unreliable_lock(const char *path, struct fuse_file_info *fi, int cmd, struct flock *fl)
{
    int ret = error_inject(path, OP_LOCK);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_lock(path, fi, cmd, fl);
}

int unreliable_ioctl(const char *path, int cmd, void *arg,
                     struct fuse_file_info *fi,
                     unsigned int flags, void *data)
{
    int ret = error_inject(path, OP_IOCTL);
    if (ret == -ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_ioctl(path, cmd, arg, fi, flags, data);
}



int unreliable_flock(const char *path, struct fuse_file_info *fi, int op) {
    int ret = error_inject(path, OP_FLOCK);
    if (ret == - ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_flock(path, fi, op);
}

int unreliable_fallocate(const char *path, int mode,
                         off_t offset, off_t len,
                         struct fuse_file_info *fi) {
    int ret = error_inject(path, OP_FALLOCATE);
    if (ret == - ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_fallocate(path, mode, offset, len, fi);
}

int unreliable_utimens(const char *path, const struct timespec ts[2]) {
    int ret = error_inject(path, OP_UTIMENS);
    if (ret == - ERRNO_NOOP) {
        return 0;
    } else if (ret) {
        return ret;
    }

    return rpc_utimens(path, ts);
}