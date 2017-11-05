cmake_minimum_required(VERSION 3.9)
project(skywifi)
set(CMAKE_CXX_FLAGS "-std=c++11 -Wno-unused-local-typedefs -Wno-unknown-warning-option ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_STANDARD 11)
find_package(Boost REQUIRED COMPONENTS system thread random)
find_package(OpenSSL REQUIRED)
set(SOURCE_FILES src/main.cpp)
add_executable(skywifi ${SOURCE_FILES})
target_include_directories(skywifi INTERFACE
        src
        ${Boost_INCLUDE_DIRS}
        src/msgpack-c/include
        src/autobahn
        ${OPENSSL_INCLUDE_DIR})
target_link_libraries(skywifi ${Boost_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT})
