cmake_minimum_required(VERSION 3.1)

project(engine LANGUAGES CUDA)
find_package(CUDA REQUIRED)
set(CUDA_NVCC_FLAGS 
-maxrregcount=0 
--ptxas-options=-v 
--compile 
--compiler-options 
-fPIC
-m64 -O4
-std=c++17
-gencode=arch=compute_61,code=sm_61
-gencode=arch=compute_75,code=sm_75 )

aux_source_directory(. SRC)

include_directories(${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES} . ../secpk1 ../utils)
cuda_add_library(${PROJECT_NAME} ${SRC})

