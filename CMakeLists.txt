project (RSAZKP)

add_executable (genrsa genrsa.c apps.c app_rand.c)
add_executable (client client.c)
add_executable (server server.c)

target_link_libraries (genrsa ssl)
