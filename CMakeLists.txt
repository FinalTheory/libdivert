cmake_minimum_required(VERSION 3.3)
project(divert)

# first build the libnids static library
add_subdirectory(libnids)

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
        divert.c
        divert_ipfw.c
        print_data.c
        print_packet.c
        queue.c
        buffer.c
        dump_packet.c
        ipfw_utils.c
        divert_kext.c
        emulator/emulator_callback.c
        emulator/emulator_config.c)

# these are used to link to apple frameworks
find_library(CORE_SERV CoreServices)
if (NOT CORE_SERV)
    message(FATAL_ERROR "CoreServices not found")
endif()

find_library(IOKIT IOKit)
if (NOT IOKIT)
    message(FATAL_ERROR "IOKit not found")
endif()

add_library(divert SHARED ${LIB_SOURCE_FILES})
target_link_libraries(divert nids pcap net ${CORE_SERV} ${IOKIT})
set_target_properties(divert PROPERTIES LINK_FLAGS -all_load SUFFIX ".so")

# below executables are demos
add_subdirectory(demo)
