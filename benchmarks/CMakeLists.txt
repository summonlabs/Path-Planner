# Guarded benchmark binary.
#
# pp_bench is not a correctness suite and is never asserted on timing: it prints
# completed operation counts plus `measurement_` labelled observations. The ctest
# entry runs the reduced --quick workload only, so a structural regression in the
# benchmarked paths is noticed without turning the suite into a performance gate.

add_executable(pp_bench pp_bench.cpp)
target_link_libraries(pp_bench PRIVATE SummonSoftwareLabs::PathPlanner)
pathplanner_apply_strict_options(pp_bench)

if(PATHPLANNER_BUILD_TESTS)
  enable_testing()
  # No timeout property: a hanging benchmark is a defect to investigate, not
  # something the harness hides by killing it.
  add_test(NAME benchmark COMMAND pp_bench --quick)
endif()
