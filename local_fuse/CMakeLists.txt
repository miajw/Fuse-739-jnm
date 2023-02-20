
add_library(local_fuse "local_fuse.cc")

target_compile_options(local_fuse PUBLIC -D_FILE_OFFSET_BITS=64 -Wall -Wextra -Wno-unused-parameter)

target_include_directories(local_fuse PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")