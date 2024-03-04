cmake_minimum_required(VERSION 3.10)
project(AdGuardTest)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address,undefined -fsanitize=leak -g")

add_executable(${PROJECT_NAME}
        main.cpp
        LiteServer.cpp
        )

find_package(OpenSSL REQUIRED)
#message(${OPENSSL_VERSION})

target_link_libraries(${PROJECT_NAME} OpenSSL::SSL pthread)
