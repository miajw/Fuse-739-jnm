
cmake_minimum_required(VERSION 3.5.1)

project(Fuse-739-jnm C CXX)

include(./common.cmake)

# build the gRPC stuff for our protobuf API
add_subdirectory(grpc_fuse)

# build the library that the unreliable filesystem uses for remote calls
add_subdirectory(remote_fuse)

# build the library that the unreliable filesystem can use to make local calls
# this is essentially the same as the default build of the unreliable file system
# except that is has all the all the debug logging that we added to unreliable_ops.c
# we are doing this so that we can figure out what part of the file system needs to
# be implemented.
add_subdirectory(local_fuse)

# build the file server which processes the remote calls
add_subdirectory(file_server)

# build the fuse server (unreliable file system)
add_subdirectory(fuse_server)
