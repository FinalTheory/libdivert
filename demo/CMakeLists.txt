# below executables are demos

add_executable(packet_by_pid packet_by_pid.c)
target_link_libraries(packet_by_pid divert)

add_executable(tcp_reassemble tcp_reassemble.c)
target_link_libraries(tcp_reassemble divert)

add_executable(dump_divert dump_divert.c)
target_link_libraries(dump_divert divert)

add_executable(violated_wifi violated_wifi.c)
target_link_libraries(violated_wifi divert)
