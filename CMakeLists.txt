cmake_minimum_required(VERSION 3.16)
project(CubeSatOTA_Simulation CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ----------------------------------------------------------
# Find OpenSSL (required for SHA-256 and Ed25519)
# ----------------------------------------------------------
find_package(OpenSSL REQUIRED)

# ----------------------------------------------------------
# Simulation executable
# ----------------------------------------------------------
add_executable(ota_sim
    sim/main.cpp
)

target_include_directories(ota_sim PRIVATE
    sim/
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(ota_sim PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_compile_options(ota_sim PRIVATE
    -Wall -Wextra -O2
)

message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "Build: ota_sim")
