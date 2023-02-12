
add_library(remote_fuse "remote_fuse.cc")

target_link_libraries(remote_fuse
        hw_grpc_proto
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        ${_PROTOBUF_LIBPROTOBUF})

target_include_directories(remote_fuse PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")