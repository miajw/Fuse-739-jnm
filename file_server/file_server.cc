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


#include <dirent.h>
#include <fcntl.h>

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

using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;
using helloworld::CommonRequest;
using helloworld::CommonResponse;
using helloworld::Data;


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


    Status generate_response(std::string cmd, std::string path, int ret, CommonResponse* response) {
        response->set_result(ret ? errno : 0);
        print_debug(cmd, path, ret);
        return Status::OK;
    }

    Status RPC_rmdir(ServerContext* context, const CommonRequest* request, CommonResponse* response) override {
        std::string path = request->path1();
        int ret = rmdir(path.c_str());
        return generate_response("RPC_rmdir", path, ret, response);
    }

    Status RPC_sendfile(ServerContext* context, const CommonRequest* request, ServerWriter<Data>* writer) override {
        std::string path = root+request->path1();
        size_t size = 0;
        uint64_t start = raw_time();

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

        if( debug_flag) {
            uint64_t elapsed = raw_time() - start;
            std::cout << "RPC_sendfile " << path << " size:" << size << " elapsed:" << elapsed << std::endl;
        }

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
