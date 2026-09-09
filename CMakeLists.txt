cmake_minimum_required(VERSION 3.11)

project(kemtls VERSION 0.1.1)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(certs)
