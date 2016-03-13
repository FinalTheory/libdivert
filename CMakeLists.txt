cmake_minimum_required(VERSION 3.3)
project(divert)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC")

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
        divert_mem_pool.c
        divert.c
        divert_ipfw.c
        print_data.c
        print_packet.c
        queue.c
        circ_buf.c
        dump_packet.c
        ipfw_utils.c
        divert_kext.c
        pqueue.c
        emulator/emulator.c
        emulator/bandwidth.c
        emulator/biterr.c
        emulator/delay.c
        emulator/disorder.c
        emulator/drop.c
        emulator/duplicate.c
        emulator/reinject.c
        emulator/throttle.c)

# these are used to link to apple frameworks
find_library(CORE_SERV CoreServices)
if (NOT CORE_SERV)
    message(FATAL_ERROR "CoreServices not found")
endif()

find_library(IOKIT IOKit)
if (NOT IOKIT)
    message(FATAL_ERROR "IOKit not found")
endif()

# first build the libnids static library
add_subdirectory(libnids)

add_library(divert SHARED ${LIB_SOURCE_FILES})
target_link_libraries(divert PRIVATE nids pcap net ${CORE_SERV} ${IOKIT})
set_property(TARGET divert APPEND PROPERTY LINK_FLAGS -all_load)
set_target_properties(divert PROPERTIES SUFFIX ".so")

add_subdirectory(demo)
add_subdirectory(test)
add_subdirectory(emulator)
