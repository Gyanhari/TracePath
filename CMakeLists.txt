cmake_minimum_required(VERSION 3.10)
project(sniffer LANGUAGES CXX)

# Use C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(sniffer
    main.cpp
    OUILookup.cpp
    PacketSniffer.cpp
)

target_include_directories(sniffer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PCAP_INCLUDE_DIRS}
)

target_link_libraries(sniffer PRIVATE ${PCAP_LIBRARIES})

