cmake_minimum_required(VERSION 3.24)

project(mc_win10_crack)

set(CMAKE_CXX_STANDARD 20)



file(GLOB_RECURSE LIB_SRC_FILES include/*.cpp)

include_directories(include)

add_library(mc_win10_crack SHARED ${LIB_SRC_FILES} dllmain.cpp)