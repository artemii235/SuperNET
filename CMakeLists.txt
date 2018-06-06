cmake_minimum_required(VERSION 3.9.2)
include("cmake/HunterGate.cmake")
HunterGate(
        URL "https://github.com/ruslo/hunter/archive/v0.19.173.tar.gz"
        SHA1 "750fb1d621af971fad6f303356b13017ad9f5e15"
        LOCAL
)
project(SuperNET)
set(DEPS_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/install)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS Off)

include(cmake/DownloadProject.cmake)

# Download and install nanomsg at CMake configure time
download_project(PROJ nanomsg
        GIT_REPOSITORY  https://github.com/nanomsg/nanomsg.git
        GIT_TAG         1.1.2
        GIT_SHALLOW     1
        GIT_PROGRESS    1
        CMAKE_ARGS      "-DNN_STATIC_LIB=ON -DNN_ENABLE_GETADDRINFO_A=OFF -DNN_ENABLE_DOC=OFF -DNN_TESTS=OFF -DNN_TOOLS=OFF -DNN_ENABLE_NANOCAT=OFF -DCMAKE_INSTALL_PREFIX=${DEPS_INSTALL_PREFIX}"
        UPDATE_DISCONNECTED 1
        )

find_library(NANOMSG_LIBRARY NAMES nanomsg PATHS ${DEPS_INSTALL_PREFIX}/lib NO_DEFAULT_PATH)
include_directories("${CMAKE_SOURCE_DIR}")
add_subdirectory(cpp-ethereum)
add_subdirectory(iguana/exchanges)
add_subdirectory(iguana/exchanges/etomicswap)
add_subdirectory(iguana/secp256k1)
add_subdirectory(crypto777)
add_subdirectory(crypto777/jpeg)