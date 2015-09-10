cmake_minimum_required(VERSION 3.3)
project(divert)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall \
-DPRIVATE \
-D_IP_VHL \
-DHAVE_STRLCPY \
-DHAVE_SNPRINTF \
-DHAVE_VSNPRINTF")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall --std=c++11")

include_directories(./include)

set(LIB_SOURCE_FILES divert.c divert_ipfw.c print_data.c print_packet.c queue.c dump_packet.c packet_buffer.c packet_info.cpp ipfw_utils.c)

add_library(divert SHARED ${LIB_SOURCE_FILES})
target_link_libraries(divert pcap)

add_executable(demo_info demo_info.c)
target_link_libraries(demo_info pcap divert)

add_executable(divert_ping demo_ping.c)
target_link_libraries(divert_ping pcap divert)
