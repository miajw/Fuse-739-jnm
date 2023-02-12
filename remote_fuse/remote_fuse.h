#ifndef REMOTE_FUSE_OPS_HH
#define REMOTE_FUSE_OPS_HH

#include <fuse.h>

int initialize_rpc();

int rpc_getattr(const char *, struct stat *);
int rpc_readlink(const char *, char *, size_t);
int rpc_mknod(const char *, mode_t, dev_t);
int rpc_mkdir(const char *, mode_t);
int rpc_unlink(const char *);
int rpc_rmdir(const char *);
int rpc_symlink(const char *, const char *);
int rpc_rename(const char *, const char *);
int rpc_link(const char *, const char *);
int rpc_chmod(const char *, mode_t);
int rpc_chown(const char *, uid_t, gid_t);
int rpc_truncate(const char *, off_t);
int rpc_open(const char *, struct fuse_file_info *);
int rpc_read(const char *, char *, size_t, off_t, struct fuse_file_info *);
int rpc_write(const char *, const char *, size_t, off_t, struct fuse_file_info *);
int rpc_statfs(const char *, struct statvfs *);
int rpc_flush(const char *, struct fuse_file_info *);
int rpc_release(const char *, struct fuse_file_info *);
int rpc_fsync(const char *, int, struct fuse_file_info *);

int rpc_setxattr(const char *, const char *, const char *, size_t, int);
int rpc_getxattr(const char *, const char *, char *, size_t);
int rpc_listxattr(const char *, char *, size_t);
int rpc_removexattr(const char *, const char *);

int rpc_opendir(const char *, struct fuse_file_info *);
int rpc_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi);
int rpc_releasedir(const char *, struct fuse_file_info *);
int rpc_fsyncdir(const char *, int, struct fuse_file_info *);

void *rpc_init(struct fuse_conn_info *conn);
void rpc_destroy(void *private_data);

int rpc_lstat(const char *path, struct stat *statbuf);
int rpc_access(const char *, int);
int rpc_create(const char *, mode_t, struct fuse_file_info *);
int rpc_ftruncate(const char *, off_t, struct fuse_file_info *);
int rpc_fgetattr(const char *, struct stat *, struct fuse_file_info *);
int rpc_lock(const char *, struct fuse_file_info *, int cmd, struct flock *);

int rpc_ioctl(const char *, int cmd, void *arg,struct fuse_file_info *, unsigned int flags, void *data);

int rpc_write_buf(const char *, struct fuse_bufvec *buf, off_t off, struct fuse_file_info *);
int rpc_read_buf(const char *, struct fuse_bufvec **bufp, size_t size, off_t off, struct fuse_file_info *);

int rpc_flock(const char *, struct fuse_file_info *, int op);
int rpc_fallocate(const char *, int, off_t, off_t, struct fuse_file_info *);
int rpc_utimens(const char *path, const struct timespec ts[2]);

#endif /* REMOTE_FUSE_OPS_HH */
