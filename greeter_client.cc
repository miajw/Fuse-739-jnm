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

#include <fuse.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

#include <grpcpp/grpcpp.h>

#ifdef BAZEL_BUILD
#include "examples/protos/helloworld.grpc.pb.h"
#else
#include "helloworld.grpc.pb.h"
#endif

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

 private:
  std::unique_ptr<Greeter::Stub> stub_;
};

GreeterClient* greeterPtr;

static int jnm_getattr( const char *path, struct stat *st )
{
    printf( "[getattr] Called\n" );
    printf( "\tAttributes of %s requested\n", path );

    st->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
    st->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
    st->st_atime = time( NULL ); // The last "a"ccess of the file/directory is right now
    st->st_mtime = time( NULL ); // The last "m"odification of the file/directory is right now

    if ( strcmp( path, "/" ) == 0 ) {
        st->st_mode = S_IFDIR | 0755;
        st->st_nlink = 2; // Why "two" hardlinks instead of "one"? The answer is here: http://unix.stackexchange.com/a/101536
    }
    else {
        st->st_mode = S_IFREG | 0644;
        st->st_nlink = 1;
        st->st_size = 1024;
    }

    return 0;
}

static int jnm_readdir( const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi ) {
    printf( "--> Getting The List of Files of %s\n", path );

    filler( buffer, ".", NULL, 0 ); // Current Directory
    filler( buffer, "..", NULL, 0 ); // Parent Directory

    if ( strcmp( path, "/" ) == 0 ) {
        filler( buffer, "file54", NULL, 0 );
        filler( buffer, "file349", NULL, 0 );
    }

    return 0;
}

extern "C" double call_remote_read(const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi) {
    std::string result = greeterPtr->SayHello(path);
    const char* data = result.c_str();

    memcpy( buffer, data + offset, size );

    return strlen( data ) - offset;

}

static int jnm_read( const char *path, char *buffer, size_t size, off_t offset, struct fuse_file_info *fi ) {
    printf( "--> Trying to read %s, %lu, %lu\n", path, offset, size );

    char file54Text[] = "Hello World From File54!";
    char file349Text[] = "Hello World From File349!";
    char *selectedText = NULL;

    // ... //

    if ( strcmp( path, "/file54" ) == 0 ) {
        selectedText = file54Text;
    } else if ( strcmp( path, "/file349" ) == 0 ) {
        selectedText = file349Text;
    } else {
        return -1;
    }

    int result = call_remote_read(path, buffer, size, offset, fi);
    return result;
}

static struct fuse_operations operations = {
        .getattr    = jnm_getattr,
        .read       = jnm_read,
        .readdir    = jnm_readdir,

};



int main(int argc, char** argv) {
  // Instantiate the client. It requires a channel, out of which the actual RPCs
  // are created. This channel models a connection to an endpoint specified by
  // the argument "--target=" which is the only expected argument.
  // We indicate that the channel isn't authenticated (use of
  // InsecureChannelCredentials()).

    std::string target_str = "localhost:50051";
    GreeterClient greeter(grpc::CreateChannel(target_str, grpc::InsecureChannelCredentials()));

    greeterPtr = &greeter;
    return fuse_main( argc, argv, &operations, NULL );
}
