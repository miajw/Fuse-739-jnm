
#include <iostream>
#include <memory>
#include <string>
#include <vector>

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

#include <grpcpp/grpcpp.h>
#include "helloworld.grpc.pb.h"

using namespace std;

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using grpc::ClientReader;


using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;
using helloworld::CommonRequest;
using helloworld::CommonResponse;
using helloworld::Data;
using helloworld::TimeSpec;
using helloworld::StatStruct;
using helloworld::StatvfsStruct;

extern int debug_flag;

class GreeterClient {
public:
    GreeterClient(std::shared_ptr <Channel> channel) : stub_(Greeter::NewStub(channel)) {}

    // Assembles the client's payload, sends it and presents the response back
    // from the server.
    std::string SayHello(const std::string &user) {
        // Data we are sending to the server.
        HelloRequest request;
        request.set_name(user);

        // Container for the data we expect from the server.
        HelloReply reply;

        // Context for the client. It could be used to convey extra information to
        // the server and/or tweak certain RPC behaviors.
        ClientContext context;

        // The actual RPC.
        Status status = stub_->SayHello(&context, request, &reply);

        // Act upon its status.
        if (status.ok()) {
            return reply.message();
        } else {
            std::cout << status.error_code() << ": " << status.error_message()
                      << std::endl;
            return "RPC failed";
        }
    }

    void print_debug(const std::string &cmd, const std::string &path, int ret) {
        if (ret) {
            if (debug_flag) {
                std::cout << cmd << " path: [" << path << "] errno:" << errno << " " << strerror(errno) << std::endl;
            }
        } else {
            if (debug_flag) {
                std::cout << cmd << " path: [" << path << "] OK" << std::endl;
            }
        }
    }

    int respond(const std::string &cmd, const std::string &path, Status status, int ret) {
        if (status.ok()) {
            if (ret) errno = ret;
            print_debug(cmd, path, ret);
            return ret ? -1 : 0;
        } else {
            if (debug_flag) {
                std::cout << cmd << " path: [" << path << "] rpc not ok -- " << status.error_code() << ": "
                          << status.error_message() << std::endl;
            }
            return -1;
        }
    }

    int getstatvfs(const  std::string& path, struct statvfs *buf) {
        CommonRequest request;
        request.set_path1(path);

        ClientContext context;
        StatvfsStruct response;
        Status status = stub_->RPC_getstatvfs(&context, request, &response);

        if (status.ok() && response.result()==0) {
            memset(buf, 0, sizeof(struct statvfs));
            buf->f_bsize = response.bsize();
            buf->f_frsize = response.frsize();
            buf->f_blocks = response.blocks();
            buf->f_bfree= response.bfree();
            buf->f_bavail = response.bavail();
            buf->f_files = response.files();
            buf->f_ffree = response.ffree();
            buf->f_favail = response.favail();
            buf->f_fsid = response.fsid();
            buf->f_flag = response.flag();
            buf->f_namemax = response.namemax();
        }

        return respond("getstatvfs", path, status, response.result());
    }

    int getattr(const std::string &path, struct stat *buf) {
        CommonRequest request;
        request.set_path1(path);

        ClientContext context;
        StatStruct response;
        Status status = stub_->RPC_getattr(&context, request, &response);

        if (status.ok() && response.result() == 0) {
            memset(buf, 0, sizeof(struct stat));
            buf->st_dev = response.dev();
            buf->st_ino = response.ino();
            buf->st_mode = response.mode();
            buf->st_nlink = response.nlink();
            buf->st_uid = response.uid();
            buf->st_gid = response.gid();
            buf->st_rdev = response.rdev();
            buf->st_size = response.size();
            buf->st_blksize = response.blksize();
            buf->st_blocks = response.blocks();
            buf->st_atim.tv_sec = response.asec();
            buf->st_atim.tv_nsec = response.anano();
            buf->st_mtim.tv_sec = response.msec();
            buf->st_mtim.tv_nsec = response.mnano();
            buf->st_ctim.tv_sec = response.csec();
            buf->st_ctim.tv_nsec = response.cnano();
        }

        return respond("getattr", path, status, response.result());
    }

    int access(const std::string& path, int mode) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(mode);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_access(&context, request, &response);
        return respond("access", path, status, response.result());
    }


    int mknod(const std::string& path, mode_t mode, dev_t dev) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(mode);
        request.set_value2(dev);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_mknod(&context, request, &response);
        return respond("mknod", path, status, response.result());
    }


    int mkdir(const std::string& path, mode_t mode) {
        fprintf(stderr, "starting mkdir\n");
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(mode);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_mkdir(&context, request, &response);
        return respond("mkdir", path, status, response.result());
    }

    int unlink(const std::string& path) {
        CommonRequest request;
        request.set_path1(path);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_unlink(&context, request, &response);
        return respond("unlink", path, status, response.result());
    }

    int rmdir(const std::string& path) {
        CommonRequest request;
        request.set_path1(path);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_rmdir(&context, request, &response);
        return respond("rmdir", path, status, response.result());
    }

    int readlink(const std::string& path, char* buffer, int bufsiz) {
        CommonRequest request;
        request.set_path1(path);

        Data response;
        ClientContext context;
        Status status = stub_->RPC_readlink(&context, request, &response);

        if (! status.ok()) {
            if (debug_flag) {
                std::cout << "readlink path: [" << path << "] rpc not ok -- " << status.error_code() << ": " << status.error_message() << std::endl;
            }
            errno = EINVAL;
            return -1;
        }

        int result = response.result();
        if(result < 0) {
            if (debug_flag) {
                std::cout << "readlink path: [" << path << "] response.result() -- " << response.result() << std::endl;
            }
            errno = -result;
            return -1;
        }

        if(result > bufsiz) result = bufsiz;
        strncpy(buffer, response.data().c_str(), result);
        return result;
    }

    int symlink(const std::string& target, const std::string& linkpath) {
        CommonRequest request;
        request.set_path1(target);
        request.set_path2(linkpath);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_symlink(&context, request, &response);
        return respond("symlink", target, status, response.result());
    }

    int rename(const std::string& oldname, const std::string& newname) {
        CommonRequest request;
        request.set_path1(oldname);
        request.set_path2(newname);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_rename(&context, request, &response);
        return respond("rename", oldname, status, response.result());
    }

    int link(const std::string& oldname, const std::string& newname) {
        CommonRequest request;
        request.set_path1(oldname);
        request.set_path2(newname);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_link(&context, request, &response);
        return respond("link", oldname, status, response.result());
    }

    int chmod(const std::string& path, mode_t mode) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(mode);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_chmod(&context, request, &response);
        return respond("chmod", path, status, response.result());
    }

    int chown(const std::string& path, int uid, int gid) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(uid);
        request.set_value2(gid);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_chown(&context, request, &response);
        return respond("chown", path, status, response.result());
    }

    int truncate(const std::string& path, off_t offset) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(offset);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_truncate(&context, request, &response);
        return respond("chown", path, status, response.result());
    }

    int utimens(const std::string& path, const struct timespec* ts) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(ts[0].tv_sec);
        request.set_value1(ts[0].tv_nsec);
        request.set_value1(ts[1].tv_sec);
        request.set_value1(ts[1].tv_nsec);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_utimens(&context, request, &response);
        return respond("chown", path, status, response.result());
    }



    int receive_file(const std::string& path, int dest_fd, size_t* size) {
        if(debug_flag) {
            std::cout << "starting receive_file " << path << " dest_fd:" << dest_fd << std::endl;
        }

        *size = 0;
        int err = 0;
        CommonRequest request;
        request.set_path1(path);

        ClientContext context;
        Data data;
        std::unique_ptr<ClientReader<Data>> reader(stub_->RPC_sendfile(&context, request));
        while (reader->Read(&data)) {
            if(data.result() != 0) {
                err = data.result();
                break;
            }

            int len = data.data().length();
            int ret = write(dest_fd, data.data().c_str(), len);
            if(ret!=len){
                err = errno;
                break;
            }
            *size += len;
        }

        Status status = reader->Finish();
        return respond("receive_file", path, status, err);
    }


    int send_file(const std::string& path, int dest_fd, size_t* size) {
        if(debug_flag) {
            std::cout << "starting send_file " << path << " dest_fd:" << dest_fd << std::endl;
        }

        *size = 0;
        int err = 0;
        CommonRequest request;
        request.set_path1(path);

        ClientContext context;
        Data data;
        std::unique_ptr<ClientReader<Data>> reader(stub_->RPC_sendfile(&context, request));
        while (reader->Read(&data)) {
            if(data.result() != 0) {
                err = data.result();
                break;
            }

            int len = data.data().length();
            int ret = write(dest_fd, data.data().c_str(), len);
            if(ret!=len){
                err = errno;
                break;
            }
            *size += len;
        }

        Status status = reader->Finish();
        return respond("receive_file", path, status, err);
    }

    int read_dir(const std::string& path, vector<string>* filenames) {
        if(debug_flag) {
            std::cout << "starting read_dir " << path << std::endl;
        }

        CommonRequest request;
        request.set_path1(path);

        ClientContext context;
        Data data;
        int err = 0;
        std::unique_ptr<ClientReader<Data>> reader(stub_->RPC_readdir(&context, request));
        while (reader->Read(&data)) {
            if(data.result() != 0) {
                err = data.result();
                break;
            }
            filenames->push_back(data.data());
        }

        Status status = reader->Finish();
        return respond("read_dir", path, status, err);
    }



    ~GreeterClient() {
        std::cout << "\n Destructor executed";
    }

private:
    std::unique_ptr<Greeter::Stub> stub_;
};

static GreeterClient* greeterPtr;

// ---------------------- our client setup / teardown stuff ----------------------

extern "C" void *rpc_init(struct fuse_conn_info *conn) {
    if(debug_flag) printf("initializing RPC\n");
    std::string target_str = "localhost:50051";
    greeterPtr = new GreeterClient(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()));
    std::string result = greeterPtr->SayHello("speedy");
    if(debug_flag) printf("called server -- result:%s\n", result.c_str());
    return NULL;
}

extern "C" void rpc_destroy(void *private_data) {
    delete greeterPtr;
}


// ---------------------- stuff to stat file and filesystems ----------------------


extern "C" int rpc_statfs(const char *path, struct statvfs *buf) {
    return greeterPtr->getstatvfs(path, buf);
}

extern "C" int rpc_lstat(const char *path, struct stat *buf) {
    return greeterPtr->getattr(path, buf);
}

extern "C" int rpc_getattr(const char *path, struct stat *buf) {
    int result = greeterPtr->getattr(path, buf);
    return result ? -errno : 0;
}



// ---------------------- stuff for manipulating files and the filesystem ----------------------

extern "C" int rpc_access(const char *path, mode_t mode) {
    return greeterPtr->access(path, mode);
}

extern "C" int rpc_mknod(const char *path, mode_t mode, dev_t dev) {
    return greeterPtr->mknod(path, mode, dev);
}

extern "C" int rpc_mkdir(const char *path, mode_t mode) {
    return greeterPtr->mkdir(path, mode);
}

extern "C" int rpc_unlink(const char *path) {
    return greeterPtr->unlink(path);
}

extern "C" int rpc_rmdir(const char *path) {
    return greeterPtr->rmdir(path);
}


extern "C" int rpc_readlink(const char *path, char *buf, size_t bufsiz) {
    return greeterPtr->readlink(path, buf, bufsiz);
}

extern "C" int rpc_symlink(const char *target, const char *linkpath) {
    return greeterPtr->symlink(target, linkpath);
}

extern "C" int rpc_rename(const char *oldpath, const char *newpath) {
    return greeterPtr->rename(oldpath, newpath);
}

extern "C" int rpc_link(const char *oldpath, const char *newpath) {
    return greeterPtr->link(oldpath, newpath);
}

extern "C" int rpc_chmod(const char *path, mode_t mode) {
    return greeterPtr->chmod(path, mode);
}

extern "C" int rpc_chown(const char *path, uid_t owner, gid_t group) {
    return greeterPtr->chown(path, owner, group);
}

extern "C" int rpc_truncate(const char *path, off_t length) {
    // TODO we probably need to truncate the local file as well (if there is one)
    return greeterPtr->truncate(path, length);
}

extern "C" int rpc_utimens(const char *path, const struct timespec ts[2]) {
    return greeterPtr->utimens(path, ts);
}


//
//public int read_file(const char *path, StreamObserver<Data> responseObserver) {) {
//    int fd = open(path, O_RDONLY);
//    if (fd == -1) {
//        Data ;
//        return;
//    }
//
//    while (1) {
//        int ret = read(fd, buf, sizeof(buf));
//        if (ret < 0) {
//            // error occured
//        } else if (ret == 0) {
//            // end of file reached
//        } else {
//            // we got data
//        }
//    }
//
//    close(fd);
//}

extern "C" int rpc_receive_file(const char *path, int fd, size_t* size) {
    return greeterPtr->receive_file(path, fd, size);
}


extern "C" int rpc_open(const char *path, struct fuse_file_info *fi)
{
    int ret = open(path, fi->flags);
    if (ret == -1) {
        return -errno;
    }
    fi->fh = ret;

    return 0;
}

extern "C" extern "C" int rpc_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
    std::string result = greeterPtr->SayHello(path);
    const char* data = result.c_str();
    memcpy( buffer, data + offset, size );
    return strlen( data ) - offset;
}

extern "C" int rpc_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    int fd;
    (void) fi;
    if(fi == NULL) {
        fd = open(path, O_WRONLY);
    } else {
        fd = fi->fh;
    }

    if (fd == -1) {
        return -errno;
    }

    int ret = pwrite(fd, buf, size, offset);
    if (ret == -1) {
        ret = -errno;
    }

    if(fi == NULL) {
        close(fd);
    }

    return ret;
}

extern "C" int rpc_flush(const char *path, struct fuse_file_info *fi)
{
    int ret = close(dup(fi->fh));
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_release(const char *path, struct fuse_file_info *fi)
{
    int ret = close(fi->fh);
    if (ret == -1) {
        return -errno;
    }

    return 0;
}

extern "C" int rpc_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
    int ret;

    if (datasync) {
        ret = fdatasync(fi->fh);
        if (ret == -1) {
            return -errno;
        }
    } else {
        ret = fsync(fi->fh);
        if (ret == -1) {
            return -errno;
        }
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


// ----------------- directory opperations (we do not support them) -----------------

extern "C" int rpc_opendir(const char *path, struct fuse_file_info *fi) {
    vector<string> filenames;
    int result = greeterPtr->read_dir(path, &filenames);
    if(result) {
        errno = - result;
        return -1;
    }
    return 0;
}

extern "C" int rpc_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    vector<string> filenames;
    int result = greeterPtr->read_dir(path, &filenames);
    if(result) {
        errno = - result;
        return -1;
    }

    uint32_t index = offset;
    while(index < filenames.size()) {
        if (filler(buf, filenames[index++].c_str(), NULL, 0)) break;
    }

    return 0;
}

extern "C" int rpc_releasedir(const char *path, struct fuse_file_info *fi) {
    return 0;
}

extern "C" int rpc_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi) {
    return 0;
}


// ----------------- extended attributes (we do not support them) -----------------

extern "C" int rpc_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
    errno = EINVAL;
    return -1;
}

extern "C" int rpc_getxattr(const char *path, const char *name, char *value, size_t size) {
    errno = ENODATA;
    return -1;
}

extern "C" int rpc_listxattr(const char *path, char *list, size_t size) {
    errno = ENODATA;
    return -1;
}

extern "C" int rpc_removexattr(const char *path, const char *name) {
    errno = EINVAL;
    return -1;
}
