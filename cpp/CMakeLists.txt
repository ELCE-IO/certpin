cmake_minimum_required(VERSION 3.16)
project(certpin_sdk LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
enable_testing()

add_library(certpin_sdk
    src/certpin.cpp
)

target_include_directories(certpin_sdk
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(certpin_sdk
    PUBLIC
        OpenSSL::Crypto
)

add_executable(certpin_sdk_tests
    tests/test_certpin.cpp
)

target_link_libraries(certpin_sdk_tests
    PRIVATE
        certpin_sdk
)

add_test(NAME certpin_sdk_tests COMMAND certpin_sdk_tests)
