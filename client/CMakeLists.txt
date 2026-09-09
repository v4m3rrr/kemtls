find_package(wolfssl CONFIG REQUIRED)

add_executable(client main.c)

target_link_libraries(client PRIVATE wolfssl::wolfssl)
