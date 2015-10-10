cmake_minimum_required(VERSION 3.3)
project(divert)

# first build the libnids static library
add_subdirectory(libnids)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall --std=c++11 -fPIC")

add_definitions(
        -DWITH_NIDS
        -DPRIVATE
        -DHAVE_STRLCPY
        -DHAVE_SNPRINTF
        -DHAVE_VSNPRINTF
)

link_directories(/usr/local/lib)
include_directories(SYSTEM ./libnids ./include ./)

set(LIB_SOURCE_FILES
        divert.c
        divert_ipfw.c
        print_data.c
        print_packet.c
        queue.c
        buffer.c
        dump_packet.c
        packet_hash.c
        ipfw_utils.c)

add_library(divert SHARED ${LIB_SOURCE_FILES})
target_link_libraries(divert nids pcap net)
set_target_properties(divert PROPERTIES LINK_FLAGS -all_load SUFFIX ".so")

# below executables are demos

add_subdirectory(demo)
