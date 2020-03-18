#!/bin/bash
git clone https://github.com/google/flatbuffers.git -b v1.11.0
cd flatbuffers
cmake -G "Unix Makefiles"
make install
chmod +x /usr/local/bin/flatc
