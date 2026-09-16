cmake_minimum_required(VERSION 3.20)

project(PathPlanner
  VERSION 1.0.0
  DESCRIPTION "Deterministic candidate-path computation runtime for the Fabric OS stack"
  HOMEPAGE_URL "https://github.com/summonlabs/Path-Planner"
  LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(PATHPLANNER_BUILD_TESTS "Build the Path Planner test suites" ON)
option(PATHPLANNER_BUILD_EXAMPLES "Build the public API examples" ON)
option(PATHPLANNER_BUILD_BENCHMARKS "Build the guarded benchmarks" ON)
option(PATHPLANNER_BUILD_CLI "Build the pathplanner CLI and node binaries" ON)
option(PATHPLANNER_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(PATHPLANNER_ENABLE_ASAN "Build with AddressSanitizer when the toolchain supports it" OFF)
option(PATHPLANNER_ENABLE_ANALYZE "Build with the MSVC static analyzer (/analyze)" OFF)

set(CMAKE_CXX_STANDARD 20 CACHE STRING "C++ standard")
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Binaries land in build/bin/<config> for multi-config generators.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------
set(PATHPLANNER_SOURCES
  src/canonical.cpp
  src/sha256.cpp
  src/status.cpp
  src/version.cpp
  src/graph.cpp
  src/path.cpp
  src/request.cpp
  src/result.cpp
  src/planning_view.cpp
  src/search.cpp
  src/planner.cpp
  src/explain.cpp
  src/proto.cpp
  src/net.cpp
  src/dist.cpp
  src/store.cpp
  src/sources.cpp
)

add_library(PathPlanner ${PATHPLANNER_SOURCES})
add_library(SummonSoftwareLabs::PathPlanner ALIAS PathPlanner)

target_include_directories(PathPlanner
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_include_directories(PathPlanner PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_features(PathPlanner PUBLIC cxx_std_20)
set_target_properties(PathPlanner PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  POSITION_INDEPENDENT_CODE ON)

if(BUILD_SHARED_LIBS)
  target_compile_definitions(PathPlanner PRIVATE PATHPLANNER_BUILDING_SHARED)
  target_compile_definitions(PathPlanner PUBLIC PATHPLANNER_SHARED)
endif()

# ---------------------------------------------------------------------------
# Compiler configuration: /W4 /WX /permissive- on MSVC, -Wall -Wextra on others.
# ---------------------------------------------------------------------------
function(pathplanner_apply_strict_options target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
    if(PATHPLANNER_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(PATHPLANNER_ENABLE_ANALYZE)
      target_compile_options(${target} PRIVATE /analyze /analyze:external- /analyze:quiet)
    endif()
    if(PATHPLANNER_ENABLE_ASAN)
      # Debug information is required for usable AddressSanitizer reports; without it MSVC
      # emits C5072, which the strict warning policy would otherwise reject.
      target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
      target_link_options(${target} PRIVATE /INCREMENTAL:NO /DEBUG)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    if(PATHPLANNER_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(PATHPLANNER_ENABLE_ASAN)
      target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
  endif()
endfunction()

pathplanner_apply_strict_options(PathPlanner)

# Stages the AddressSanitizer runtime next to an executable so instrumented binaries
# (and the child processes tests spawn) can run without a PATH change.
function(pathplanner_stage_asan_runtime target)
  if(MSVC AND PATHPLANNER_ENABLE_ASAN AND PATHPLANNER_ASAN_RUNTIME_DIR)
    file(GLOB _pp_asan_dlls "${PATHPLANNER_ASAN_RUNTIME_DIR}/clang_rt.asan_*.dll")
    foreach(dll IN LISTS _pp_asan_dlls)
      add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${dll}" "$<TARGET_FILE_DIR:${target}>")
    endforeach()
  endif()
endfunction()

if(MSVC AND PATHPLANNER_ENABLE_ASAN)
  # Locate the MSVC AddressSanitizer runtime (it sits beside cl.exe) so it can be
  # staged next to every executable. Diagnosed at configure time; never assumed.
  get_filename_component(_pp_compiler_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
  file(GLOB _pp_asan_runtimes "${_pp_compiler_dir}/clang_rt.asan_dynamic-*.dll")
  if(_pp_asan_runtimes)
    set(PATHPLANNER_ASAN_RUNTIME_DIR "${_pp_compiler_dir}" CACHE INTERNAL "ASan runtime directory")
    message(STATUS "  ASan runtime:      ${_pp_compiler_dir}")
  else()
    message(WARNING "AddressSanitizer was requested but no runtime was found next to cl.exe")
  endif()
endif()

# ---------------------------------------------------------------------------
# Installation and package export
# ---------------------------------------------------------------------------
install(TARGETS PathPlanner
  EXPORT PathPlannerTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT PathPlannerTargets
  FILE PathPlannerTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PathPlanner)

configure_package_config_file(
  cmake/PathPlannerConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/PathPlannerConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PathPlanner)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/PathPlannerConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/PathPlannerConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/PathPlannerConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PathPlanner)

# ---------------------------------------------------------------------------
# Subdirectories
# ---------------------------------------------------------------------------
if(PATHPLANNER_BUILD_CLI)
  add_subdirectory(apps)
endif()
if(PATHPLANNER_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(PATHPLANNER_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()
if(PATHPLANNER_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Version report
# ---------------------------------------------------------------------------
message(STATUS "PathPlanner ${PROJECT_VERSION} (planning rules ${PROJECT_VERSION_MAJOR}.0.0)")
message(STATUS "  AddressSanitizer: ${PATHPLANNER_ENABLE_ASAN}")
message(STATUS "  Static analyzer:  ${PATHPLANNER_ENABLE_ANALYZE}")
