cmake_minimum_required(VERSION 3.10)

project(POSEFT_HANDSHAKE)

set(DEP_DIR deps)
set(CMAKE_C_FLAGS "-g -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -DITEX_OPENSSL")
set(CMAKE_CXX_FLAGS "-g -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -DITEX_OPENSSL")

add_compile_options(-fpic)

file(GLOB XML_SRCS "ezxml/*.c")
file(GLOB C8583_SRCS "c8583/*.c")
file(GLOB DES_SRCS "des/*.c")
file(GLOB SHA256_SRCS "sha256/*.c")
file(GLOB PLATFORM_SRCS "platform/*.c")
file(GLOB RC4_SRCS "rc4/*.c")

add_library(xmldep STATIC ${XML_SRCS})
add_library(c8583 STATIC ${C8583_SRCS})
add_library(des STATIC ${DES_SRCS})
add_library(sha256 STATIC ${SHA256_SRCS})
add_library(platform STATIC ${PLATFORM_SRCS})
add_library(rc4 STATIC ${RC4_SRCS})

file(GLOB EFT_SRC "${PROJECT_SOURCE_DIR}/src/*.c")

add_library(poseft_handshake SHARED ${EFT_SRC})
target_include_directories(poseft_handshake PRIVATE ${PROJECT_SOURCE_DIR}/inc ".")
target_compile_options(poseft_handshake PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(poseft_handshake sqlite3 xmldep c8583 des sha256 platform rc4)

find_package(OpenSSL REQUIRED)

if(OpenSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
    message(STATUS "Using OpenSSL ${OPENSSL_INCLUDE_DIRS}")
    message(STATUS "Using OpenSSL ${OPENSSL_LIBRARIES}")
endif(OpenSSL_FOUND)

set(TEST_TARGET poseft_handshake_tests)
file(GLOB HANDSHAKEAPP_SRC "${PROJECT_SOURCE_DIR}/tests/*.c")
add_executable(${TEST_TARGET} ${HANDSHAKEAPP_SRC})
target_include_directories(${TEST_TARGET} PRIVATE ${PROJECT_SOURCE_DIR}/${DEP_DIR} ".")
target_link_libraries(${TEST_TARGET} poseft_handshake ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})

message(STATUS "Compiler is : ${CMAKE_C_COMPILER}")
