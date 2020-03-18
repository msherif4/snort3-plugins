#!/bin/bash

# Download zeromq
# Ref http://zeromq.org/intro:get-the-software
wget https://github.com/zeromq/libzmq/releases/download/v4.2.2/zeromq-4.2.2.tar.gz

# Unpack tarball package
tar xvzf zeromq-4.2.2.tar.gz

# Install dependency
apt-get update && \
apt-get install -y libtool pkg-config build-essential autoconf automake uuid-dev

# Create make file
cd zeromq-4.2.2
./configure

# Build and install(root permission only)
make install

# Create libzmq debian pkg 
checkinstall -y -d0 --pkgname libzmq --backup=no --strip=no --stripso=no --install=no

# Install
chmod -R 777 /plugin/zeromq-4.2.2/libzmq_4.2.2-1_amd64.deb
apt-get install -y -f /plugin/zeromq-4.2.2/libzmq_4.2.2-1_amd64.deb
