FROM ubuntu:17.10
RUN apt-get update && apt-get install -y git libcurl4-openssl-dev build-essential wget pax libleveldb-dev && apt-get clean
RUN wget https://cmake.org/files/v3.10/cmake-3.10.3-Linux-x86_64.sh && \
    chmod +x cmake-3.10.3-Linux-x86_64.sh && \
    ./cmake-3.10.3-Linux-x86_64.sh --skip-license --exclude-subdir --prefix=/usr && \
    rm -rf cmake-3.10.3-Linux-x86_64.sh
CMD rm -rf build && mkdir build && cd build && cmake .. && cmake --build . --target marketmaker-testnet
