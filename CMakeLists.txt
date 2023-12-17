cmake_minimum_required(VERSION 3.24)

project(mc_win10_crack)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O -s -fno-rtti -fno-exceptions")

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  add_compile_options(-Wno-dynamic-class-memaccess -Wno-microsoft-goto -Wno-delete-incomplete /EHsc /Ob1)
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
endif()

add_compile_definitions(WIN32_LEAN_AND_MEAN)
add_compile_definitions(NOMINMAX)

file(GLOB_RECURSE LIB_SRC_FILES include/*.cpp)

include_directories(include)

add_library(mc_win10_crack SHARED ${LIB_SRC_FILES} dllmain.cpp)