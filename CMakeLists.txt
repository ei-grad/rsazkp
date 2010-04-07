cmake_minimum_required(VERSION 2.8)

project (RSAZKP)

add_subdirectory (doc)

add_library (apps STATIC apps.c app_rand.c)

add_executable (genrsa genrsa.c)
add_executable (rsazkp rsazkp.c client.c server.c)

target_link_libraries (genrsa ssl apps)
target_link_libraries (rsazkp ssl apps)
