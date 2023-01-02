cmake_minimum_required(VERSION 3.22)
project(libpwsafe 
    VERSION 0.1.0 
    DESCRIPTION "Library for reading and writing Passwordsafe account database files" 
)

include_directories(api)
include_directories(include)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wall -Wextra")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wall -Wextra")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb -O0 -fsanitize=address,undefined")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb -O0 -fsanitize=address,undefined")

add_subdirectory(src)
add_subdirectory(api)

enable_testing()

add_subdirectory(test)
