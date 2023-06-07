cmake_minimum_required(VERSION 3.1)

project(catch_kangaroo)

if(BUILD_CUDA)
add_subdirectory(engine)
set(LIBS ${LIBS} engine)
add_compile_definitions(WITHGPU)
endif()
set(CMAKE_CXX_FLAGS " ${CMAKE_CXX_FLAGS} -std=c++17 -m64 -mssse3 -Wno-unused-result -Wno-write-strings -Wno-format -fno-stack-protector -O4")

set(CMAKE_PREFIX_PATH "/usr/lib/x86_64-linux-gnu")
find_package(hiredis REQUIRED)
find_package(redis++ REQUIRED)

include_directories(kangaroo network secpk1 storage utils engine)
aux_source_directory(kangaroo KANGAROO_SRC)
aux_source_directory(network NETWORK_SRC)
aux_source_directory(secpk1 SECPK1_SRC)
aux_source_directory(storage STORAGE_SRC)
aux_source_directory(utils UTILS_SRC)

add_library(kangaroo  ${KANGAROO_SRC}
${NETWORK_SRC}
${SECPK1_SRC}
${STORAGE_SRC}
${UTILS_SRC})

target_link_libraries(kangaroo  redis++ pthread ssl crypto)

add_executable(${PROJECT_NAME} main.cpp )

target_link_libraries(${PROJECT_NAME}  kangaroo  ${LIBS})


add_executable(storageTest  ${CMAKE_CURRENT_SOURCE_DIR}/test/storageTest.cpp)

target_link_libraries(storageTest  kangaroo ${LIBS})


