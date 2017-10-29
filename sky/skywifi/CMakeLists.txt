cmake_minimum_required(VERSION 3.9)
project(crossbar_sky)
set(CMAKE_CXX_FLAGS "-std=c++11 -Wno-unused-local-typedefs -Wno-unknown-warning-option ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_STANDARD 11)
find_package(Boost REQUIRED COMPONENTS system thread random)
find_package(OpenSSL REQUIRED)
set(SOURCE_FILES src/main.cpp)
add_library(skywifilib src/skywifi.cpp)
add_executable(skywifi ${SOURCE_FILES})
target_include_directories(skywifi INTERFACE
        src
        ${Boost_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/msgpack-c/include
        ${SOURCE_FILES}/src/autobahn
        ${OPENSSL_INCLUDE_DIR})
target_link_libraries(skywifi skywifilib ${Boost_LIBRARIES}
        sqlite3
        ${OPENSSL_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT})
configure_file(src/config.json src/config.json COPYONLY)