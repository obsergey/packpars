cmake_minimum_required(VERSION 3.7)
project(packpars)

set(CMAKE_CXX_STANDARD 17)

include(FindPCAP.cmake)

set(SOURCE_FILES main.cpp Parser.cpp Processor.cpp)
add_executable(packpars ${SOURCE_FILES})
target_link_libraries(packpars ${PCAP_LIBRARY})
