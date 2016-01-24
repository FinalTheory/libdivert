cmake_minimum_required(VERSION 3.3)
project(demo)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -O2")

# below executables are demos

add_executable(test_mem_pool test_mem_pool.c)
target_link_libraries(test_mem_pool divert)
