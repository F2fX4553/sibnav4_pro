cmake_minimum_required(VERSION 3.10)
project(secure_protocol_cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)
include_directories(../../core/target/release) # For header if generated there, or ../c/

# We need to link against the Rust static library
# Assuming it's built in core/target/release
find_library(RUST_LIB secure_protocol PATHS ../../core/target/release NO_DEFAULT_PATH)

add_library(secure_protocol_cpp SHARED
    src/secure_protocol.cpp
)

target_link_libraries(secure_protocol_cpp PRIVATE 
    ${RUST_LIB}
    # On Linux we need pthread and dl usually
    pthread
    dl
)

if(WIN32)
    target_link_libraries(secure_protocol_cpp PRIVATE ws2_32 userenv advapi32 ntdll)
endif()
