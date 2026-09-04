cmake_minimum_required(VERSION 3.16)
# DynamoRIO 11.3 仍通过 CMAKE_COMPILER_IS_GNUCC 判断 Linux 工具链。
# 同时启用 C，防止纯 C++ client 被误报为使用了非 GNU linker。
project(bmo_trace LANGUAGES C CXX)

find_package(DynamoRIO CONFIG REQUIRED)
add_library(bmo_trace SHARED client.cpp)
target_compile_features(bmo_trace PRIVATE cxx_std_17)
configure_DynamoRIO_client(bmo_trace)
use_DynamoRIO_extension(bmo_trace drmgr)
use_DynamoRIO_extension(bmo_trace drreg)
use_DynamoRIO_extension(bmo_trace drutil)
use_DynamoRIO_extension(bmo_trace drwrap)
