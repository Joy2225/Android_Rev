cmake_minimum_required(VERSION 3.22.1)

# Set project name
project("dynamic")

# Create libdynamic.so
add_library(dynamic SHARED
        dynamic.cpp
)

# Create libanti.so
add_library(anti SHARED
        anti.c
)

# Link necessary libraries to both shared libraries
target_link_libraries(dynamic
        android
        log
)

target_link_libraries(anti
        android
        log
)
