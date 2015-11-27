cmake_minimum_required(VERSION 3.3)
project(demo)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -O2")


add_executable(emulator emulator_test.c)
target_link_libraries(emulator divert)
