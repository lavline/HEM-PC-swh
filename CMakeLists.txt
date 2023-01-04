cmake_minimum_required(VERSION 3.11)
#set(CMAKE_C_COMPILER /usr/bin/gcc)
project(HEM)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -march=native -O3 -mavx2 ")
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB_RECURSE SRC_LIST "src/*.cpp" "src/*.h")
add_executable(main ${SRC_LIST})