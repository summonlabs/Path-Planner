# The target name differs from the produced binary name so that the generated project
# files cannot collide with the PathPlanner library project on case-insensitive hosts.
add_executable(pathplanner_cli pp_cli.cpp)
set_target_properties(pathplanner_cli PROPERTIES OUTPUT_NAME pathplanner)
target_link_libraries(pathplanner_cli PRIVATE SummonSoftwareLabs::PathPlanner)
pathplanner_apply_strict_options(pathplanner_cli)
pathplanner_stage_asan_runtime(pathplanner_cli)

install(TARGETS pathplanner_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
