cmake_minimum_required(VERSION 3.3)
project(divert)

add_subdirectory(libnids)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -g")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall --std=c++11 -fPIC")

add_definitions(
        -DPRIVATE
        -D_IP_VHL
        -DHAVE_STRLCPY
        -DHAVE_SNPRINTF
        -DHAVE_VSNPRINTF
)

include_directories(SYSTEM ./libnids ./include ./)

set(LIB_SOURCE_FILES
        divert.c
        divert_ipfw.c
        print_data.c
        print_packet.c
        queue.c
        buffer.c
        dump_packet.c
        packet_info.cpp
        ipfw_utils.c)

add_library(divert SHARED ${LIB_SOURCE_FILES})
target_link_libraries(divert pcap)
target_link_libraries(divert nids -all_load)
set_target_properties(divert PROPERTIES SUFFIX ".so")

# below executables are demos

add_executable(demo_info demo/packet_detail.c)
target_link_libraries(demo_info divert)

add_executable(demo_blockIO demo/packet_detail_blockio.c)
target_link_libraries(demo_blockIO divert)

add_executable(divert_ping demo/divert_ping.c)
target_link_libraries(divert_ping divert)

add_executable(tcp_reassemble demo/tcp_reassemble.c)
target_link_libraries(tcp_reassemble divert)
