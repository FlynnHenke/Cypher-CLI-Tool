cmake_minimum_required(VERSION 3.10)

set(This CLI-CYPHER)

project(${This} C CXX) 

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)


set(Headers
    src/cypher.h
)
set(Sources
    src/cypher.c
    src/main.c
    src/utilities.c
)

add_library(${This} STATIC ${Sources} ${Headers})
include_directories(src)

add_executable(cypher
    src/main.c
    src/cypher.c
    src/utilities.c)