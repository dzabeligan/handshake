#!/usr/bin/env bash

# Already built so we can comment out this line, uncomment if you haven't
cc keyCheck.c des/*.c -o keyCheck

./keyCheck -d 4821d7d8faf6e217be964222a37d2190 F2B8F619EC8651E4272E4B2F000BF462
./keyCheck 85FB7FC4588332AB975E9E04409B897F 1600FF
./keyCheck -d 11111111111111111111111111111111 F40379AB9E0EC533F40379AB9E0EC533