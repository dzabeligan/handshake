#!/usr/bin/env bash

# run in build directory
make -j4
./poseft_handshake_tests &>../logs/log.log
