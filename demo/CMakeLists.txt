cmake_minimum_required(VERSION 3.3)
project(demo)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -O2")

# below executables are demos

add_executable(demo_info packet_detail.c)
target_link_libraries(demo_info divert)

add_executable(demo_blockIO packet_detail_blockio.c)
target_link_libraries(demo_blockIO divert)

add_executable(divert_ping divert_ping.c)
target_link_libraries(divert_ping divert)

add_executable(tcp_reassemble tcp_reassemble.c)
target_link_libraries(tcp_reassemble divert)
