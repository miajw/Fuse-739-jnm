
add_executable(file_server "file_server.cc")

target_link_libraries(file_server
        hw_grpc_proto
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        ${_PROTOBUF_LIBPROTOBUF})
