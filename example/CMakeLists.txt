# Works with 3.11 and tested through 3.15
cmake_minimum_required(VERSION 3.11...3.16)

# Project name and a few useful settings. Other commands can pick up the results
project(example VERSION 0.1)

# Only do these if this is the main project, and not if it is included through add_subdirectory
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    # Optionally set things like CMAKE_CXX_STANDARD, CMAKE_POSITION_INDEPENDENT_CODE here

    # Let's ensure -std=c++xx instead of -std=g++xx
    set(CMAKE_CXX_EXTENSIONS OFF)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    # Let's nicely support folders in IDE's
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()

add_executable(example main.cpp)
target_compile_features(example PRIVATE cxx_std_17)
