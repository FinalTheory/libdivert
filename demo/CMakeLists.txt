cmake_minimum_required(VERSION 3.3)
project(demo)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -O2")

# below executables are demos

add_executable(packet_by_pid packet_by_pid.c)
target_link_libraries(packet_by_pid divert)

add_executable(tcp_reassemble tcp_reassemble.c)
target_link_libraries(tcp_reassemble divert)

add_executable(dump_divert dump_divert.c)
target_link_libraries(dump_divert divert)

add_executable(gfw_simulator gfw_simulator.c)
target_link_libraries(gfw_simulator divert)
