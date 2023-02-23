/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>




#include <grpcpp/ext/proto_server_reflection_plugin.h>
#include <grpcpp/grpcpp.h>
#include <grpcpp/health_check_service_interface.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::ServerWriter;
using grpc::ServerReader;

using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;
using helloworld::CommonRequest;
using helloworld::CommonResponse;
using helloworld::ReceiveFileRequest;
using helloworld::ReceiveFileResponse;
using helloworld::Data;
using helloworld::TimeSpec;
using helloworld::StatStruct;
using helloworld::StatvfsStruct;


/**
 * returns the number of nanoseconds since the beginning oof the epoch (1/1/    1970)
 */
uint64_t raw_time() {
    struct timespec tstart;
    clock_gettime(CLOCK_MONOTONIC, &tstart);
    return ((uint64_t)tstart.tv_sec)*100000000000L + ((uint64_t)tstart.tv_nsec);
}


std::string root = "";
int debug_flag = 0;

// Logic and data behind the server's behavior.
class GreeterServiceImpl final : public Greeter::Service {
  Status SayHello(ServerContext* context, const HelloRequest* request, HelloReply* reply) override {
    std::string prefix("Hello ");
    reply->set_message(prefix + request->name());
    return Status::OK;
  }

    void print_debug(std::string cmd, std::string path, int ret) {
        if(debug_flag) {
            if(ret) {
                std::cout << cmd << " path: [" << path << "] ret:" << ret << " errno:" << errno << " " << strerror(errno) << std::endl;
            } else {
                std::cout << cmd << " path: [" << path << "] OK" << std::endl;
            }
        }
    }

    Status generate_response(std::string cmd, std::string path, int ret, CommonResponse* response, uint64_t start) {
        response->set_result(ret ? errno : 0);
        if(debug_flag) {
            uint64_t elapsed = raw_time() - start;
            if(ret) {
                std::cout << cmd << " path: [" << path << "] ret:" << ret << " errno:" << errno << " " << strerror(errno) << " elapsed:" << elapsed << std::endl;
            } else {
                std::cout << cmd << " path: [" << path << "] OK" << " elapsed:" << elapsed << std::endl;
            }
        }
        return Status::OK;
    }

    Status RPC_getstatvfs(ServerContext* context, const CommonRequest* request, StatvfsStruct* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();

        struct statvfs buf;
        memset(&buf, 0, sizeof(struct statvfs));
        int result = statvfs(path.c_str(), &buf);
        if(result < 0) {
            response->set_result(errno ? errno : EINVAL);
            print_debug("RPC_getstatvfs--statvfs", path, result);
            return Status::OK;
        }

        response->set_result(0);
        response->set_bsize(buf.f_bsize);
        response->set_frsize(buf.f_frsize);
        response->set_blocks(buf.f_blocks);
        response->set_bfree(buf.f_bfree);
        response->set_bavail(buf.f_bavail);
        response->set_files(buf.f_files);
        response->set_ffree(buf.f_ffree);
        response->set_favail(buf.f_favail);
        response->set_fsid(buf.f_fsid);
        response->set_flag(buf.f_flag);
        response->set_namemax(buf.f_namemax);

        if(debug_flag) {
            uint64_t elapsed = raw_time() - start;
            std::cout << "RPC_getstatvfs " << path << " elapsed:" << elapsed << std::endl;
        }

        return Status::OK;
    }


    Status RPC_getattr(ServerContext* context, const CommonRequest* request, StatStruct* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();

        struct stat buf;
        memset(&buf, 0, sizeof(struct stat));
        int result = lstat(path.c_str(), &buf);
        if(result < 0) {
            response->set_result(errno);
            print_debug("RPC_getattr--lstat", path, result);
            return Status::OK;
        }

        response->set_result(0);
        response->set_dev(buf.st_dev);
        response->set_ino(buf.st_ino);
        response->set_mode(buf.st_mode);
        response->set_nlink(buf.st_nlink);
        response->set_uid(buf.st_uid);
        response->set_gid(buf.st_gid);
        response->set_rdev(buf.st_rdev);
        response->set_size(buf.st_size);
        response->set_blksize(buf.st_blksize);
        response->set_blocks(buf.st_blocks);

        response->set_asec(buf.st_atim.tv_sec);
        response->set_anano(buf.st_atim.tv_nsec);
        response->set_msec(buf.st_atim.tv_sec);
        response->set_mnano(buf.st_mtim.tv_nsec);
        response->set_csec(buf.st_ctim.tv_sec);
        response->set_cnano(buf.st_ctim.tv_nsec);

        if(debug_flag) {
            uint64_t elapsed = raw_time() - start;
            std::cout << "RPC_getattr " << path << " size:" << buf.st_size << " elapsed:" << elapsed << std::endl;
        }

        return Status::OK;
    }


    Status RPC_access(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();
        int ret = access(path.c_str(), request->value1());
        return generate_response("RPC_access", path, ret, response, start);
    }

    Status RPC_mknod(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();
        int ret = mknod(path.c_str(), request->value1(), request->value2());
        return generate_response("RPC_mknod", path, ret, response, start);
    }

    Status RPC_mkdir(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string path = root + "/filesystem" + request->path1();
        int ret = mkdir(path.c_str(), request->value1());
        return generate_response("RPC_mkdir", path, ret, response, start);
    }

    Status RPC_unlink(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();
        int ret = unlink(path.c_str());
        return generate_response("RPC_unlink", path, ret, response, start);
    }

    Status RPC_rmdir(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();
        int ret = rmdir(path.c_str());
        return generate_response("RPC_rmdir", path, ret, response, start);
    }

    Status RPC_readlink(ServerContext* context, const CommonRequest* request, Data* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();

        char buffer[4096];
        int ret = readlink(path.c_str(), buffer, sizeof(buffer));
        if(ret < 0) {
            response->set_result(ret ? errno : 0);
        } else {
            response->set_result(0);
            response->set_data(std::string(buffer, ret));
        }

        if(debug_flag) {
            uint64_t elapsed = raw_time() - start;
            if(ret) {
                std::cout << "RPC_readlink path: [" << path << "] ret:" << ret << " errno:" << errno << " " << strerror(errno) << " elapsed:" << elapsed << std::endl;
            } else {
                std::cout << "RPC_readlink path: [" << path << "] OK" << " elapsed:" << elapsed << std::endl;
            }
        }

        return Status::OK;
    }

    Status RPC_symlink(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string target = root+"/filesystem"+request->path1();
        std::string linkpath = request->path2();
        int ret = symlink(target.c_str(), linkpath.c_str());
        return generate_response("RPC_symlink", linkpath, ret, response, start);
    }

    Status RPC_rename(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string oldname = root+"/filesystem"+request->path1();
        std::string newname = root+"/filesystem"+request->path2();
        int ret = rename(oldname.c_str(), newname.c_str());
        return generate_response("RPC_rename", oldname, ret, response, start);
    }

    Status RPC_link(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string oldname = root+"/filesystem"+request->path1();
        std::string newname = root+"/filesystem"+request->path2();
        int ret = link(oldname.c_str(), newname.c_str());
        return generate_response("RPC_link", oldname, ret, response, start);
    }

    Status RPC_chmod(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();
        int ret = chmod(path.c_str(), request->value1());
        return generate_response("RPC_chmod", path, ret, response, start);
    }

    Status RPC_chown(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();
        int ret = chown(path.c_str(), request->value1(), request->value2());
        return generate_response("RPC_chown", path, ret, response, start);
    }

    Status RPC_truncate(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();
        int ret = truncate(path.c_str(), request->value1());
        return generate_response("RPC_truncate", path, ret, response, start);
    }

    Status RPC_utimens(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();
        struct timespec ts[2];
        ts[0].tv_sec = request->value1();
        ts[0].tv_nsec = request->value2();
        ts[1].tv_sec = request->value3();
        ts[1].tv_nsec = request->value4();
        int ret = utimensat(AT_FDCWD, path.c_str(), ts, AT_SYMLINK_NOFOLLOW);
        return generate_response("RPC_utimens", path, ret, response, start);
    }






    // sends the requested file to client
    Status RPC_sendfile(ServerContext* context, const CommonRequest* request, ServerWriter<Data>* writer) override {
        uint64_t start = raw_time();
        std::string path = root+request->path1();
        size_t size = 0;


        int fd = open(path.c_str(), O_RDONLY);
        if (fd == -1) {
            print_debug("RPC_sendfile--open", path, fd);
            Data data = Data();
            data.set_result(errno);
            writer->Write(data);
            return Status::OK;
        }

        char buffer[65536];

        while (1) {
            int ret = read(fd, buffer, sizeof(buffer));
            if (ret < 0) {
                // got an error
                print_debug("RPC_sendfile--read", path, fd);
                Data data = Data();
                data.set_result(errno);
                writer->Write(data);
                break;
            } else if (ret == 0) {
                // end of file reached
                break;
            } else {
                // we got data
                size += ret;
                Data data = Data();
                data.set_result(0);
                data.set_data(std::string(buffer, ret));
                writer->Write(data);
            }
        }

        int close_result = close(fd);
        if(close_result) {
            print_debug("RPC_sendfile--close", path, close_result);
        }

        if(debug_flag) {
            uint64_t elapsed = raw_time() - start;
            std::cout << "RPC_sendfile " << path << " size:" << size << " elapsed:" << elapsed << std::endl;
        }

        return Status::OK;
    }

    // sends all the filenames in the speciffied dir
    Status RPC_readdir(ServerContext* context, const CommonRequest* request, ServerWriter<Data>* writer) override {
        uint64_t start = raw_time();
        std::string path = root+"/filesystem"+request->path1();

        DIR *dp = opendir(path.c_str());
        if (dp == NULL) {
            print_debug("RPC_readdir--opendir", path, 0);
            Data data = Data();
            data.set_result(errno ? errno : EINVAL);
            writer->Write(data);
            return Status::OK;
        }

        int entries = 0;
        struct dirent *de;
        while ((de = readdir(dp)) != NULL) {
            Data data = Data();
            data.set_result(0);
            data.set_data(std::string(de->d_name));
            writer->Write(data);
            entries++;
        }

        int result = closedir(dp);
        if(result) {
            print_debug("RPC_readdir--closedir", path, result);
        }

        if(debug_flag) {
            uint64_t elapsed = raw_time() - start;
            std::cout << "RPC_readdir " << path << " entries:" << entries << " elapsed:" << elapsed << std::endl;
        }

        return Status::OK;
    }


    std::string get_random_name() {
        int fd = open("/dev/random", O_RDONLY);
        if (fd == -1) {
            print_debug("get_random_name--open", "/dev/random", fd);
            return std::string("");
        }
        char buffer[17];
        for (int i = 0; i < 16; i++) {
            char ch;
            int ret = read(fd, &ch, 1);
            if (ret == -1) {
                close(fd);
                print_debug("get_random_name--read", "/dev/random",ret);
                return std::string("");
            }
            buffer[i] = 'a' + ch % 26;
        }
        close(fd);
        buffer[16] = 0;
        return std::string(buffer);
    }

    Status RPC_receivefile(ServerContext* context, ServerReader<ReceiveFileRequest>* reader, ReceiveFileResponse* response) override {
        uint64_t start = raw_time();

        size_t size = 0;

        // get a temporary file name to land the file while we receive data
        std::string temp = get_random_name();
        if(temp.length()==0) {
            print_debug("RPC_receivefile--get_random_name", temp, 0);
            response->set_result(errno ? errno : EINVAL);
            return Status::OK;
        }

        // set temp to the full path in our filesystem.
        temp = root+"/staging/"+get_random_name();

        int fd = open(temp.c_str(), O_WRONLY);
        if (fd == -1) {
            print_debug("RPC_receivefile--open", temp, fd);
            response->set_result(errno ? errno : EINVAL);
            return Status::OK;
        }

        bool isFirst = true;
        std::string filename;
        uint64_t expected_size;
        uint32_t mode;
        uint32_t uid;
        uint32_t gid ;

        ReceiveFileRequest data;
        while (reader->Read(&data)) {
            if(isFirst) {
                filename = std::string(data.filename());
                expected_size = data.size();
                mode = data.mode();
                uid = data.uid();
                gid = data.gid();
                isFirst = false;
            }

            std::string bytes = data.data();
            int len = bytes.length();
            size += len;
            int ret = write(fd, bytes.c_str(), len);
            if (ret != len) {
                // got an error
                close(fd);
                unlink(temp.c_str());
                print_debug("RPC_receivefile--write", temp, fd);
                response->set_result(errno ? errno : EINVAL);
                return Status::OK;
            }
        }

        // WTF? we did not get anything from the stream
        if(isFirst) {
            print_debug("RPC_receivefile--close", filename, 0);
            response->set_result(EINVAL);
            return Status::OK;
        }

        int result = close(fd);
        if(result) {
            unlink(temp.c_str());
            print_debug("RPC_receivefile--close", temp, result);
            response->set_result(errno ? errno : EINVAL);
            return Status::OK;
        }

        // make sure we wrote the same number of bytes that the client asked us to write
        if(size != expected_size) {
            unlink(temp.c_str());
            print_debug("RPC_receivefile--wrong size received", temp, result);
            response->set_result(errno ? errno : EINVAL);
            return Status::OK;
        }

        // set the permissions to whatever the client has requested
        result = chmod(temp.c_str(), mode);
        if (result < 0) {
            unlink(temp.c_str());
            print_debug("RPC_receivefile--chmod", temp, result);
            response->set_result(errno ? errno : EINVAL);
            return Status::OK;
        }

        // set the file ownership to whatever the client requested
        result = chown(temp.c_str(), uid, gid);
        if (result < 0) {
            unlink(temp.c_str());
            print_debug("RPC_receivefile--chown", temp, result);
            response->set_result(errno ? errno : EINVAL);
            return Status::OK;
        }


//        struct timespec ts[2];
//        ts[0].tv_sec
//
//        printf("ts[0] %ld.%09ld\n", ts[0].tv_sec, ts[0].tv_nsec);
//        printf("ts[1] %ld.%09ld\n", ts[1].tv_sec, ts[1].tv_nsec);
//
//        int ret = utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
//        if (ret == -1) {
//            printf("utimensat failed errno:%d\n", errno);
//            return -errno;
//        }

        // get the full path name for the file in our local file system
        std::string newpath = root +"/filesystem" + filename;
        std::cout << "newpath:" << newpath << newpath << std::endl;

        result = rename(temp.c_str(), newpath.c_str());
        if (result < 0) {
            unlink(temp.c_str());
            print_debug("RPC_receivefile--rename", temp, result);
            response->set_result(errno ? errno : EINVAL);
            return Status::OK;
        }

//        struct stat buf;
//        memset(&buf, 0, sizeof(struct stat));
//        result = lstat(newpath.c_str(), &buf);
//        if (result < 0) {
//            print_debug("RPC_receivefile--lstat", newpath, result);
//            response->set_result(errno ? errno : EINVAL);
//            return Status::OK;
//        }

        if( debug_flag) {
            uint64_t elapsed = raw_time() - start;
            std::cout << "RPC_receivefile " << filename << " size:" << size << " elapsed:" << elapsed << std::endl;
        }

        response->set_result(0);
        return Status::OK;
    }
};

void RunServer() {
  std::string server_address("0.0.0.0:50051");
  GreeterServiceImpl service;

  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  ServerBuilder builder;
  // Listen on the given address without any authentication mechanism.
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  // Register "service" as the instance through which we'll communicate with
  // clients. In this case it corresponds to an *synchronous* service.
  builder.RegisterService(&service);
  // Finally assemble the server.
  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;

  // Wait for the server to shutdown. Note that some other thread must be
  // responsible for shutting down the server for this call to ever return.
  server->Wait();
}

void usage(char* name, char* msg) {
    printf("error: %s\n", msg);
    printf("usage: %s -d -r <path to root>\n", name);
    printf("-d: debug mode -- prints out lots of stuff\n");
    exit(-1);
}

int main(int argc, char** argv) {

    int c = 0;
    while ((c = getopt (argc, argv, "dr:")) != -1) {
        switch (c) {
            case 'd':
                debug_flag = 1;
                break;
            case 'r':
                root = std::string(optarg);
                break;
            default:
                abort();
        }
    }

    if(root.length() == 0) {
        usage(argv[0], (char*) "root is required!");
    }

    DIR *dir = opendir(root.c_str());
    if(dir == NULL) {
        usage(argv[0], (char*) "could opendir the root");
    }
    closedir(dir);

    if(debug_flag) {
        printf("%s starting with filesystem root:[%s]\n", argv[0], root.c_str());
    }

    RunServer();
    return 0;
}
