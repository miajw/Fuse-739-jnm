
add_executable(file_server "file_server.cc")
add_executable(test_utimens "test_utimens.c")

target_link_libraries(file_server
        hw_grpc_proto
        ${_REFLECTION}
        ${_GRPC_GRPCPP}
        ${_PROTOBUF_LIBPROTOBUF})
