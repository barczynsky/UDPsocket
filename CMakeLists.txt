cmake_minimum_required(VERSION 3.1)
project(UDPsocket)

# -----------------------------------------------------------------------------
# CMake preferences
# -----------------------------------------------------------------------------
# set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_BUILD_TYPE Release)
# set(CMAKE_BUILD_TYPE RelWithDebInfo)
# set(CMAKE_BUILD_TYPE MinSizeRel)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})


# -----------------------------------------------------------------------------
# C++ compiler flags
# -----------------------------------------------------------------------------
if(${CMAKE_CXX_COMPILER_ID} MATCHES "Clang")
	set(AUX_CXX_FLAGS "${AUX_CXX_FLAGS} -Wall -Wextra -pedantic")
	set(AUX_CXX_FLAGS "${AUX_CXX_FLAGS} -fcolor-diagnostics")
elseif(${CMAKE_CXX_COMPILER_ID} MATCHES "MSVC")
	set(AUX_CXX_FLAGS "${AUX_CXX_FLAGS} /Wall")
	set(AUX_CXX_FLAGS "${AUX_CXX_FLAGS} /std:c++latest")
endif()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${AUX_CXX_FLAGS}")

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 17)


# -----------------------------------------------------------------------------
# find_package(), include_directories()
# -----------------------------------------------------------------------------
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)


# -----------------------------------------------------------------------------
# include_directories()
# -----------------------------------------------------------------------------
include_directories(".")
include_directories("include")


# -----------------------------------------------------------------------------
# ${SRC}, aux_source_directory()
# -----------------------------------------------------------------------------
# aux_source_directory("src" SRC)


# -----------------------------------------------------------------------------
# ${LIBS}
# -----------------------------------------------------------------------------
# if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
# 	set(LIBS ${LIBS} "glfw")
# 	set(LIBS ${LIBS} "Xi;Xrandr;Xcursor;Xxf86vm")
# endif()


# -----------------------------------------------------------------------------
# add_subdirectory(), add_executable()
# -----------------------------------------------------------------------------
add_executable(broadcast "tests/broadcast.cpp")
target_link_libraries(broadcast ${CMAKE_THREAD_LIBS_INIT} ${LIBS})

message("")


# -----------------------------------------------------------------------------
# add_custom_target()
# -----------------------------------------------------------------------------
#if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
#	message(">> Use 'deps' target to install missing dependencies.")
#	message("")
#	add_custom_target(deps)
#endif()


# -----------------------------------------------------------------------------
# CMake summary, message()
# -----------------------------------------------------------------------------
message("-- SRC:   ${SRC}")
message("-- LIBS:  ${LIBS}")
message("")
