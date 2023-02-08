# this script should get all the required packages to build and install gRPC.
#
sudo apt-get update
sudo apt-get -y install build-essential autoconf libtool pkg-config
sudo apt-get -y install git
sudo apt-get -y install cmake
sudo apt-get -y install libfuse-dev
sudo apt-get -y install zlib1g-dev
sudo apt-get -y install zip
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg integrate install
./vcpkg install grpc
