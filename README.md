# Fuse-739-jnm

Set Up
------

# get the get_deps.sh file and execute it.
it will build get all our dependencies and build gRPC (it takes a long time the first time)


# command to make the Makefile
cmake .. "-DCMAKE_TOOLCHAIN_FILE=/home/ubuntu/vcpkg/scripts/buildsystems/vcpkg.cmake"

# to build the project

cd Fuse-739-jnm 
mkdir build
cmake .. "-DCMAKE_TOOLCHAIN_FILE=/home/ubuntu/vcpkg/scripts/buildsystems/vcpkg.cmake"
make


