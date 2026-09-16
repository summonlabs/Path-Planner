cmake_minimum_required(VERSION 3.20)

# Independent downstream consumer of the installed PathPlanner package.
#
# This project is deliberately NOT part of the Path Planner build: it exists to prove
# that the installed package is usable from a separate CMake project with no access to
# the Path Planner source tree. Build it against an installed prefix:
#
#   cmake -S consumer -B <build> -DCMAKE_PREFIX_PATH=<install-prefix>
#   cmake --build <build> --config Release
#   <build>/consumer_plan_check
project(PathPlannerConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PathPlanner CONFIG REQUIRED)

if(NOT TARGET SummonSoftwareLabs::PathPlanner)
  message(FATAL_ERROR "SummonSoftwareLabs::PathPlanner was not exported by the installed package")
endif()

message(STATUS "PathPlanner package version: ${PathPlanner_VERSION}")

add_executable(consumer_plan_check main.cpp)
target_link_libraries(consumer_plan_check PRIVATE SummonSoftwareLabs::PathPlanner)
