set(CMAKE_MAKE_PROGRAM /usr/bin/make)
set(CMAKE_C_COMPILER /usr/bin/gcc)
set(CMAKE_CXX_COMPILER /usr/bin/g++)
set(FUSE_LIBRARIES /usr/lib/x86_64-linux-gnu/libfuse.so)
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")
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
add_subdirectory(fuse_server)
