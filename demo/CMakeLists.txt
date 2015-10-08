cmake_minimum_required(VERSION 3.3)
project(demo)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -O2")

# below executables are demos

add_executable(packet_proc_pktap packet_proc_pktap.c)
target_link_libraries(packet_proc_pktap divert)

add_executable(demo_block_read demo_block_read.c)
target_link_libraries(demo_block_read divert)

add_executable(delay_ping delay_ping.c)
target_link_libraries(delay_ping divert)

add_executable(tcp_reassemble tcp_reassemble.c)
target_link_libraries(tcp_reassemble divert)

add_executable(dump_divert dump_divert.c)
target_link_libraries(dump_divert divert)
