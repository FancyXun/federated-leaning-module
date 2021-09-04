cmake_minimum_required(VERSION 2.8.12)
project(libpts)

find_package(PythonInterp REQUIRED)
include_directories(${PYTHON_INCLUDE_DIRS})

add_subdirectory(pybind11)

# List all c and cpp files
file(GLOB HOMO_CPP_LIST homomorph/*.cpp)
file(GLOB HOMO_H_LIST homomorph/*.h)
file(GLOB HOMO_CPU_CPP_LIST homomorph/cpu/*.cpp)
file(GLOB HOMO_CPU_H_LIST homomorph/cpu/*.h)
pybind11_add_module(libpts ${HOMO_CPP_LIST} ${HOMO_H_LIST} ${HOMO_CPU_CPP_LIST} ${HOMO_CPU_H_LIST})

include_directories(/usr/include /usr/lib /usr/include/eigen3)

target_link_libraries(libpts PUBLIC /usr/local/lib/libgmp.so)
target_link_libraries(libpts PUBLIC /usr/lib/x86_64-linux-gnu/libgmpxx.so)
target_link_libraries(libpts PUBLIC /usr/lib/x86_64-linux-gnu/libssl.so)
target_link_libraries(libpts PUBLIC /usr/lib/x86_64-linux-gnu/libcrypto.so)
target_link_libraries(libpts PUBLIC /usr/local/lib/libhcs.so)