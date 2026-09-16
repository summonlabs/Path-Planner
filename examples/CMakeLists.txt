# Public API examples.
#
# One executable per example source so a reader can build and run a single
# scenario. Each executable is also registered with ctest: an example that stops
# printing the outcome it promises exits non-zero, so ctest fails with it.

set(PATHPLANNER_EXAMPLES
  quickstart
  constraints
  lifecycle
)

# The top-level CMakeLists enables testing after the subdirectories have been
# added, so enable it here as well (idempotent) to guarantee that the example
# tests land in this directory's CTestTestfile.cmake.
if(PATHPLANNER_BUILD_TESTS)
  enable_testing()
endif()

foreach(example IN LISTS PATHPLANNER_EXAMPLES)
  add_executable(example_${example} example_${example}.cpp)
  target_link_libraries(example_${example} PRIVATE SummonSoftwareLabs::PathPlanner)
  pathplanner_apply_strict_options(example_${example})
  add_test(NAME example_${example} COMMAND example_${example})
endforeach()
