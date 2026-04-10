cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(Duk3Sniffer)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(Duk3Sniffer
  sniffer.cpp
)

target_link_libraries(Duk3Sniffer PRIVATE ${PCAP_LIBRARIES})

target_include_directories(Duk3Sniffer PRIVATE ${PCAP_INCLUDE_DIRS})
