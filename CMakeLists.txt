cmake_minimum_required(VERSION 3.12)
project(webserver)

set(CMAKE_CXX_STANDARD 17)

add_executable(webserver main.cpp static/static_const.h)