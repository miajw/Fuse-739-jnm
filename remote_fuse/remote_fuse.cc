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

#define FUSE_USE_VERSION 30

#include <grpcpp/grpcpp.h>
#include "helloworld.grpc.pb.h"


using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using helloworld::Greeter;
using helloworld::HelloReply;
using helloworld::HelloRequest;

class GreeterClient {
public:
    GreeterClient(std::shared_ptr<Channel> channel)
            : stub_(Greeter::NewStub(channel)) {}

    // Assembles the client's payload, sends it and presents the response back
    // from the server.
    std::string SayHello(const std::string& user) {
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

    ~GreeterClient() {
        std::cout << "\n Destructor executed";
    }

private:
    std::unique_ptr<Greeter::Stub> stub_;
};

static GreeterClient* greeterPtr;

extern "C" int initialize_rpc() {
    std::string target_str = "localhost:50051";
    greeterPtr = new GreeterClient(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()));
    std::string result = greeterPtr->SayHello("speedy");
    printf("called server -- result:%s\n", result.c_str());
    return 0;
}

extern "C" int rpc_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
    std::string result = greeterPtr->SayHello(path);
    const char* data = result.c_str();
    memcpy( buffer, data + offset, size );
    return strlen( data ) - offset;
}
