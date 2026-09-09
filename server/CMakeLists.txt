find_package(wolfssl CONFIG REQUIRED)

add_executable(server main.c)

target_link_libraries(server PRIVATE wolfssl::wolfssl)
