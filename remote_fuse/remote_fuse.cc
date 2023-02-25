
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
#include <sys/stat.h>
#include <sys/xattr.h>
#include <openssl/sha.h>

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
using grpc::ClientWriter;


using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;
using helloworld::CommonRequest;
using helloworld::CommonResponse;
using helloworld::Data;
using helloworld::WritebackRequest;
using helloworld::WritebackResponse;
using helloworld::StatStruct;
using helloworld::StatvfsStruct;

extern int debug_flag;
extern int print_errors;

char* cache_path = (char*) "/home/ubuntu/fuse_cache/";

void set_value(uint8_t value, int offset, char* buffer) {
    if(value<10) {
        buffer[offset] = '0' + value;
    } else {
        buffer[offset] = 'a' + value - 10;
    }
}

void to_hex(uint8_t value, int offset, char* buffer) {
    uint8_t hi = (value >> 4) & 0xf;
    uint8_t lo = value & 0xf;
    set_value(hi, offset, buffer);
    set_value(lo, offset+1, buffer);
}

void hash_name(const unsigned char* in, char* result) {
    unsigned char hash[SHA_DIGEST_LENGTH]; // == 20
    int len = strlen((const char *)in);
    SHA1(in, len, hash);

    strcpy(result, cache_path);
    int offset = strlen(cache_path);
    // this is a really cheesy way to create the filename but ...
    for(int i=0; i<20; i++) {
        to_hex(hash[i], offset+i*2, result);
    }
    result[offset+40] = 0;
}


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

    void print_error(const std::string &cmd, const std::string &msg, const std::string &path, int result) {
        std::cout << cmd << " " << msg << " path: [" << path << "] result:" << result
        << " errno:" << errno
        << " " << strerror(errno) << std::endl;
    }


    void print_debug(const std::string &cmd, const std::string &path, int ret) {
        if (ret) {
            if(print_errors) {
                std::cout << cmd << " path: [" << path << "] errno:" << errno << " " << strerror(errno) << std::endl;
            }
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
            if (debug_flag || print_errors) {
                std::cout << cmd << " path: [" << path << "] rpc not ok -- " << status.error_code() << ": "
                          << status.error_message() << std::endl;
            }
            return -1;
        }
    }

    int remote_getstatvfs(const  std::string& path, struct statvfs *buf) {
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

    int remote_getattr(const std::string &path, struct stat *buf) {
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

        int ret = response.result();

        // no such file is common when getting file attributes
        // we won't consider this case an error and will just return
        if(status.ok() && ret == 2 && debug_flag==0) {
            errno = 2;
            return -1;
        }

        return respond("getattr", path, status, ret);
    }

    int remote_access(const std::string& path, int mode) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(mode);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_access(&context, request, &response);
        return respond("access", path, status, response.result());
    }


    int remote_mknod(const std::string& path, mode_t mode, dev_t dev) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(mode);
        request.set_value2(dev);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_mknod(&context, request, &response);
        return respond("mknod", path, status, response.result());
    }


    int remote_mkdir(const std::string& path, mode_t mode) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(mode);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_mkdir(&context, request, &response);
        return respond("mkdir", path, status, response.result());
    }

    int remote_create(const std::string& path, mode_t mode) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(mode);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_create(&context, request, &response);
        return respond("create", path, status, response.result());
    }

    int remote_unlink(const std::string& path) {
        CommonRequest request;
        request.set_path1(path);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_unlink(&context, request, &response);
        return respond("unlink", path, status, response.result());
    }

    int remote_rmdir(const std::string& path) {
        CommonRequest request;
        request.set_path1(path);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_rmdir(&context, request, &response);
        return respond("rmdir", path, status, response.result());
    }

    int remote_readlink(const std::string& path, char* buffer, int bufsiz) {
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

    int remote_symlink(const std::string& target, const std::string& linkpath) {
        CommonRequest request;
        request.set_path1(target);
        request.set_path2(linkpath);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_symlink(&context, request, &response);
        return respond("symlink", target, status, response.result());
    }

    int remote_rename(const std::string& oldname, const std::string& newname) {
        CommonRequest request;
        request.set_path1(oldname);
        request.set_path2(newname);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_rename(&context, request, &response);
        return respond("rename", oldname, status, response.result());
    }

    int remote_link(const std::string& oldname, const std::string& newname) {
        CommonRequest request;
        request.set_path1(oldname);
        request.set_path2(newname);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_link(&context, request, &response);
        return respond("link", oldname, status, response.result());
    }

    int remote_chmod(const std::string& path, mode_t mode) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(mode);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_chmod(&context, request, &response);
        return respond("chmod", path, status, response.result());
    }

    int remote_chown(const std::string& path, int uid, int gid) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(uid);
        request.set_value2(gid);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_chown(&context, request, &response);
        return respond("chown", path, status, response.result());
    }

    int remote_truncate(const std::string& path, off_t offset) {
        CommonRequest request;
        request.set_path1(path);
        request.set_value1(offset);

        CommonResponse response;
        ClientContext context;
        Status status = stub_->RPC_truncate(&context, request, &response);
        return respond("chown", path, status, response.result());
    }

    int remote_utimens(const std::string& path, const struct timespec* ts) {
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

    int remote_read_dir(const std::string& path, vector<string>* filenames) {
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

    int cached_copy_usable(const std::string& path, char* hash_path) {
        struct stat local_stat;
        memset(&local_stat, 0, sizeof(struct stat));
        int result = lstat(hash_path, &local_stat);
        if(result == 2) {
            // no such file or directory
            unlink(hash_path);
            return 1;
        }
        if(result != 0) return 0;

        struct stat remote_stat;
        result = remote_getattr(path, &remote_stat);
        if(result != 0)  return 0;

        if (local_stat.st_size != remote_stat.st_size) return 0;
        if (local_stat.st_mtim.tv_sec == remote_stat.st_mtim.tv_sec ) return 0;
        if (local_stat.st_mtim.tv_nsec == remote_stat.st_mtim.tv_nsec) return 0;

        return 1;
    }


    int do_fetch_file(const std::string& path, char* hash_path) {

        struct stat remote_stat;
        int rret = remote_getattr(path, &remote_stat);
        if(rret != 0) {
            printf("getattr failed -- path:%s rret:%d\n", path.c_str(), rret);
            return rret; // try again
        }

        int dest_fd = open(hash_path, O_CREAT | O_TRUNC | O_WRONLY);
        if(dest_fd < 0) return dest_fd;
        printf("opened file %s fd:%d\n", hash_path, dest_fd);

        CommonRequest request;
        request.set_path1(path);

        size_t size = 0;
        ClientContext context;
        Data data;
        std::unique_ptr<ClientReader<Data>> reader(stub_->RPC_fetchfile(&context, request));
        while (reader->Read(&data)) {
            if(data.result() != 0) {
                break;
            }

            int len = data.data().length();
            int ret = pwrite(dest_fd, data.data().c_str(), len, size);
            if(ret!=len){
                std::string msg = "write fd:"+std::to_string(dest_fd)+" offset:"+std::to_string(size)+" len:"+std::to_string(len);
                print_error("fetchfile", msg, path, ret);
                break;
            }
            size = size + len;
        }

        // clean up
        Status status = reader->Finish();
        if(!status.ok()) {
            printf("finish screwed up\n");
            return -2;
        }

        int result = close(dest_fd);
        if(result) {
            printf("close screwed up\n");
            return -2;
        }

        // make sure the file did not change on the server while we downloaded.
        struct stat remote_stat2;
        rret = remote_getattr(path, &remote_stat2);
        if(rret != 0) {
            printf("file changed while downloading path:%s rret:%d\n", path.c_str(), rret);
            return -2; // try again
        }

        if (remote_stat2.st_size != remote_stat.st_size ||
            remote_stat2.st_mtim.tv_sec != remote_stat.st_mtim.tv_sec ||
            remote_stat2.st_mtim.tv_nsec != remote_stat.st_mtim.tv_nsec) {
            printf("file changed while downloading:%s\n", path.c_str());
            return -2;  // try again
        }

        printf("chmod to %o\n", remote_stat2.st_mode);

        // set the permissions to whatever the client has requested
        result = chmod(hash_path, remote_stat2.st_mode);
        if (result < 0) {
            printf("do_fetch_file--chmod %s %d\n", hash_path, result);
            return -2;
        }

        printf("chown to uid%d gid:%d\n", remote_stat2.st_uid, remote_stat2.st_gid);

        // set the file ownership to whatever the client requested
        result = chown(hash_path, remote_stat2.st_uid, remote_stat2.st_gid);
        if (result < 0) {
            printf("do_fetch_file--chmod %s %d\n", hash_path, result);
            return -2;
        }

        struct timespec ts[2];
        ts[0].tv_sec = remote_stat2.st_atim.tv_sec;
        ts[0].tv_nsec = remote_stat2.st_atim.tv_nsec;
        ts[1].tv_sec = remote_stat2.st_mtim.tv_sec;
        ts[1].tv_nsec = remote_stat2.st_mtim.tv_nsec;

        result = utimensat(AT_FDCWD, hash_path, ts, AT_SYMLINK_NOFOLLOW);
        if (result == -1) {
            printf("do_fetch_file--utimensat failed errno:%d\n", errno);
            return -2;
        }

         // the file changed while downloading
        printf("do_fetch_file file downloaded path:%s\n", path.c_str());
        return 0;
    }

    int fetchfile(const std::string& path, char* hash_path) {

        int attempts = 0;
        while (attempts < 10) {
            if(cached_copy_usable(path, hash_path)) {
                printf("cached file is reeusable - YAY!\n");
                return 0;
            }

            int result = do_fetch_file(path, hash_path);
            if (result != -2) return result;
            attempts++;
        }

        printf("%d attempts to fetch file: %s\n", attempts, path.c_str());
        errno = EAGAIN;
        return -1;
    }



    int writeback(const std::string& path) {
        char hash_path[256];
        hash_name((const unsigned char*)path.c_str(), hash_path);

        if (debug_flag) {
            printf("starting writeback path:%s, hash_path:%s\n", path.c_str(), hash_path);
        }

        struct stat buf;
        memset(&buf, 0, sizeof(struct stat));
        int retval = lstat(hash_path, &buf);
        if(retval < 0) {
            std::string msg = "lstat hash_path:"+std::string(hash_path);
            print_error("writeback", msg, path, retval);
            return -1;
        }

        WritebackRequest request;
        request.set_filename(path);
        request.set_size(buf.st_size);
        request.set_mode(buf.st_mode);
        request.set_uid(buf.st_uid);
        request.set_gid(buf.st_gid);

        if(debug_flag) {
            std::cout << "path:" << path
                    << " st_size:" << buf.st_size
                    << " st_mode:" << buf.st_mode
                    << " st_uid:" << buf.st_uid
                    << " st_gid:" << buf.st_gid << std::endl;
        }

        int fd = open(hash_path, O_RDONLY);
        if(fd < 0) {
            std::string msg = "open hash_path:"+std::string(hash_path);
            print_error("writeback", msg, path, retval);
            return -1;
        }

        ClientContext context;
        WritebackResponse response;
        std::unique_ptr<ClientWriter<WritebackRequest>> writer(stub_->RPC_writeback(&context, &response));
        size_t size = 0;

        char buffer[65536];
        while (1) {
            int ret = pread(fd, buffer, sizeof(buffer), size);
            if (ret < 0) {
                // got an error
                std::string msg = "pread fd:"+std::to_string(fd)+" offset:"+std::to_string(size);
                print_error("writeback", msg, path, retval);
                WritebackRequest request = WritebackRequest();
                writer->Write(request);
                break;
            } else if (ret == 0) {
                // end of file reached
                break;
            } else {
                // we got data
                size += ret;
                request.set_data(std::string(buffer, ret));
                writer->Write(request);
            }
        }
        
        int close_result = close(fd);
        if (close_result) {
            std::string msg = "close fd:"+std::to_string(fd)+" offset:"+std::to_string(size);
            print_error("writeback", msg, path, retval);
        }

        writer->WritesDone();
        Status status = writer->Finish();
        return respond("writeback", path, status, 0);
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
    return greeterPtr->remote_getstatvfs(path, buf);
}

extern "C" int rpc_lstat(const char *path, struct stat *buf) {
    return greeterPtr->remote_getattr(path, buf);
}

extern "C" int rpc_getattr(const char *path, struct stat *buf) {
    int result = greeterPtr->remote_getattr(path, buf);
    return result ? -errno : 0;
}



// ---------------------- stuff for manipulating files and the filesystem ----------------------

extern "C" int rpc_access(const char *path, mode_t mode) {
    return greeterPtr->remote_access(path, mode);
}

extern "C" int rpc_mknod(const char *path, mode_t mode, dev_t dev) {
    return greeterPtr->remote_mknod(path, mode, dev);
}

extern "C" int rpc_mkdir(const char *path, mode_t mode) {
    return greeterPtr->remote_mkdir(path, mode);
}

extern "C" int rpc_unlink(const char *path) {
    return greeterPtr->remote_unlink(path);
}

extern "C" int rpc_rmdir(const char *path) {
    return greeterPtr->remote_rmdir(path);
}


extern "C" int rpc_readlink(const char *path, char *buf, size_t bufsiz) {
    return greeterPtr->remote_readlink(path, buf, bufsiz);
}

extern "C" int rpc_symlink(const char *target, const char *linkpath) {
    return greeterPtr->remote_symlink(target, linkpath);
}

extern "C" int rpc_rename(const char *oldpath, const char *newpath) {
    return greeterPtr->remote_rename(oldpath, newpath);
}

extern "C" int rpc_link(const char *oldpath, const char *newpath) {
    return greeterPtr->remote_link(oldpath, newpath);
}

extern "C" int rpc_chmod(const char *path, mode_t mode) {
    return greeterPtr->remote_chmod(path, mode);
}

extern "C" int rpc_chown(const char *path, uid_t owner, gid_t group) {
    return greeterPtr->remote_chown(path, owner, group);
}

extern "C" int rpc_truncate(const char *path, off_t length) {
    // TODO we probably need to truncate the local file as well (if there is one)
    return greeterPtr->remote_truncate(path, length);
}

extern "C" int rpc_utimens(const char *path, const struct timespec ts[2]) {
    return greeterPtr->remote_utimens(path, ts);
}


extern "C" int rpc_open(const char *path, struct fuse_file_info *fi)
{
    if(fi->flags & O_CREAT) {
        printf("************** rpc_open with O_CREAT  path:%s flags:%d\n", path, fi->flags);
    }

    char hash_path[256];
    hash_name((const unsigned char*)path, hash_path);
    printf("rpc_open hash_path: [%s]\n", hash_path);

    int result = greeterPtr->fetchfile(path, hash_path);
    if (result < 0) {
        printf("rpc_open path:%s errno:%d strerror:%s\n", path, errno, strerror(errno));
        return result;
    }

    printf("rpc_open fetched the file\n");

    int ret = open(hash_path, O_RDWR);
    if(ret < 0) {
        printf("rpc_open path:%s hash_path:%s flags:%d errno:%d strerror:%s\n", path, hash_path, fi->flags, errno, strerror(errno));
        return ret;
    }

    fi->fh = ret;

    return 0;
}


extern "C" int rpc_release(const char *path, struct fuse_file_info *fi) {

    int ret = greeterPtr->writeback(path);

    close(fi->fh);
    fi->fh = -1;

    return ret;
}

extern "C" int rpc_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
    if(fi == NULL) return -EINVAL;

    int ret = pread(fi->fh, buffer, size, offset);
    if (ret == -1) return -errno;

    return ret;
}

extern "C" int rpc_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    if(fi == NULL) return -EINVAL;

    int ret = pwrite(fi->fh, buf, size, offset);
    if (ret == -1) {
        ret = -errno;
    }

    return ret;
}

extern "C" int rpc_flush(const char* path, struct fuse_file_info* fi)
{
    int ret = close(dup(fi->fh));
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

extern "C" int rpc_create(const char *path, mode_t mode, struct fuse_file_info* fi) {
     int ret = greeterPtr->remote_create(path, mode);
     if(ret != 0) return ret;
     return rpc_open(path, fi);
}

extern "C" int rpc_ftruncate(const char *path, off_t length, struct fuse_file_info *fi)
{
    int ret = greeterPtr->remote_truncate(path, length);
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


// ----------------- directory operations (we do not support them) -----------------

extern "C" int rpc_opendir(const char *path, struct fuse_file_info *fi) {
    vector<string> filenames;
    int result = greeterPtr->remote_read_dir(path, &filenames);
    if(result) {
        errno = - result;
        return -1;
    }
    return 0;
}

extern "C" int rpc_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    vector<string> filenames;
    int result = greeterPtr->remote_read_dir(path, &filenames);
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
