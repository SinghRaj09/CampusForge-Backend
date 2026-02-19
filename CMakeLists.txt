cmake_minimum_required(VERSION 3.15)
project(CampusConnect)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Required packages
find_package(cpr REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

# Add executable
add_executable(CampusConnect
    src/main.cpp
)

# Include directories (target scoped)
target_include_directories(CampusConnect PRIVATE
    ${PROJECT_SOURCE_DIR}/external/Crow-master/include
    ${PROJECT_SOURCE_DIR}/external/asio-1.36.0/include
    ${PROJECT_SOURCE_DIR}/external/jwt-cpp/include
    ${PROJECT_SOURCE_DIR}/src
)

# Link libraries
target_link_libraries(CampusConnect PRIVATE
    cpr::cpr
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
)

# Windows-specific networking libs
if (WIN32)
    target_link_libraries(CampusConnect PRIVATE
        ws2_32
        mswsock
    )
endif()
