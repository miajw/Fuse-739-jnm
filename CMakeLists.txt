
cmake_minimum_required(VERSION 3.5.1)

project(Fuse-739-jnm C CXX)

include(./common.cmake)

# build the gRPC stuff for our protobuf API
add_subdirectory(grpc_fuse)

# build the library that the unreliable filesystem uses for remote calls
add_subdirectory(remote_fuse)

# build the file server which processes the remote calls
add_subdirectory(file_server)

# build the fuse server (unreliable file system)
add_subdirectory(unreliablefs)
