cmake_minimum_required(VERSION 3.1)

project(network)

aux_source_directory(. SRC)
add_library(${PROJECT_NAME} ${SRC})
