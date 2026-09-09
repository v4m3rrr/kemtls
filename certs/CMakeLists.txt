find_package(wolfssl CONFIG REQUIRED)

add_executable(cert main.c sig_algo.c gen_key.c )
add_executable(test test.c sig_algo.c gen_key.c cert_gen.c)

target_link_libraries(cert PRIVATE wolfssl::wolfssl)
target_link_libraries(test PRIVATE wolfssl::wolfssl)
