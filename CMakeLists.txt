#[[
   Copyright 2022 The Silkpre Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
]]

# ethash requires cmake 3.16.2
cmake_minimum_required(VERSION 3.16.2)

option(SILKPRE_TESTING "Build tests and test tools" OFF)

get_directory_property(SILKPRE_HAS_PARENT PARENT_DIRECTORY)
if(NOT SILKPRE_HAS_PARENT)
    if(NOT CMAKE_TOOLCHAIN_FILE)
        set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain.cmake CACHE FILEPATH "" FORCE)
    endif()

    if(SILKPRE_TESTING)
        set(HUNTER_PACKAGES Catch)
    endif()

    include(FetchContent)
    FetchContent_Declare(SetupHunter GIT_REPOSITORY https://github.com/cpp-pm/gate)
    FetchContent_MakeAvailable(SetupHunter)
endif()

project(silkpre)

# libff
set(CURVE "ALT_BN128" CACHE STRING "" FORCE)
option(WITH_PROCPS "" OFF)
option(IS_LIBFF_PARENT "" OFF)
if(MSVC)
    option(MPIR_INSTEAD_OF_GMP "" ON)
endif()
add_subdirectory(third_party/libff)

add_subdirectory(lib)

if(SILKPRE_TESTING)
    add_subdirectory(test)
endif()
