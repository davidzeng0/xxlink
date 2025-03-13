cmake_minimum_required(VERSION 3.16)
project(xetrov-link CXX)
cmake_policy(SET CMP0069 NEW)
include(CheckIPOSupported)
check_ipo_supported()
include(FetchContent)

option(XE_FLTO "Enable full program optimization on release mode" ON)
set(XE_ENABLE_XURL ON)
set(XE_USE_WOLFSSL ON)
set(XE_ENABLE_EXAMPLES OFF)

FetchContent_Declare(xetrov GIT_REPOSITORY https://github.com/davidzeng0/xetrov.git GIT_TAG master)
FetchContent_MakeAvailable(xetrov)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -Wall")

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "11")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines")
	endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

	if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "14")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fcoroutines-ts")
	endif()
endif()

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -mtune=native")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O3 -g -march=native -mtune=native")
if((NOT ${CMAKE_BUILD_TYPE} STREQUAL "Debug") AND XE_FLTO)
	set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

set(SOURCES "")
file(GLOB SOURCES
	"src/*.cc"
	"src/voice/*.cc"
	"src/resource/*.cc"
	"src/proto/*.cc"
	"src/proto/commands/*.cc"
)

include_directories("src/proto")

add_library(xetrov-link ${SOURCES})
target_include_directories(xetrov-link INTERFACE include)
target_link_libraries(xetrov-link xe xetrov wolfssl protobuf)

add_executable(node "executable/node.cc")
target_link_libraries(node xetrov-link)