# The race suite also carries the real-process distributed proofs (worker death and
# fencing, coordinator restart and conservative recovery), so no separate suite is needed.
set(PATHPLANNER_TEST_SUITES
  core
  oracle
  adversarial
  race
  sources
)

foreach(suite IN LISTS PATHPLANNER_TEST_SUITES)
  add_executable(pp_tests_${suite} test_main.cpp ${suite}_tests.cpp)
  target_link_libraries(pp_tests_${suite} PRIVATE SummonSoftwareLabs::PathPlanner)
  target_include_directories(pp_tests_${suite} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
  pathplanner_apply_strict_options(pp_tests_${suite})
  if(WIN32)
    target_compile_definitions(pp_tests_${suite} PRIVATE _CRT_SECURE_NO_WARNINGS)
  endif()
  # The distributed suite orchestrates real processes through the CLI binary.
  target_compile_definitions(pp_tests_${suite} PRIVATE
    PP_CLI_BINARY="$<TARGET_FILE:pathplanner_cli>")
  add_dependencies(pp_tests_${suite} pathplanner_cli)
  add_test(NAME ${suite} COMMAND pp_tests_${suite})
  pathplanner_stage_asan_runtime(pp_tests_${suite})
endforeach()
