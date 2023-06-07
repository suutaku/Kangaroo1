cmake_minimum_required(VERSION 3.1)

project(catch_kangaroo)

if(BUILD_CUDA)
add_subdirectory(engine)
set(LIBS ${LIBS} engine)
add_compile_definitions(WITHGPU)
endif()

set(CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS} -m64 -mssse3 -Wno-unused-result -Wno-write-strings -Wno-format -fno-stack-protector -O4")


include_directories(kangaroo network secpk1 storage utils engine)
aux_source_directory(kangaroo KANGAROO_SRC)
aux_source_directory(network NETWORK_SRC)
aux_source_directory(secpk1 SECPK1_SRC)
aux_source_directory(storage STORAGE_SRC)
aux_source_directory(utils UTILS_SRC)

add_executable(${PROJECT_NAME} main.cpp 
${KANGAROO_SRC}
${NETWORK_SRC}
${SECPK1_SRC}
${STORAGE_SRC}
${UTILS_SRC}
)

target_link_libraries(${PROJECT_NAME} ${LIBS} pthread ssl crypto)
