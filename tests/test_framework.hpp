#pragma once

// Minimal deterministic test harness. No external dependencies, no timeouts, no
// fixed ports, no hidden global state beyond the case registry.

#include <cstdint>
#include <exception>
#include <functional>
#include <string>
#include <vector>

namespace pp_test {

struct Failure {
  std::string message;
};

struct Case {
  std::string suite;
  std::string name;
  std::function<void()> body;
};

// Global counters. Tests are single threaded; the distributed suite spawns
// processes but asserts from the test thread only.
extern std::uint64_t g_checks;
extern std::uint64_t g_failures;
extern std::string g_current;

std::vector<Case>& Registry();

struct Registrar {
  Registrar(const char* suite, const char* name, std::function<void()> body);
};

void Fail(const char* file, int line, const std::string& message);

// Comparison indirection: keeping the predicate inside a function call prevents the
// compiler front end from seeing a syntactically constant condition (C4127 under /W4 /WX)
// when both operands are literal constants.
template <class Lhs, class Rhs>
bool EqualValues(const Lhs& lhs, const Rhs& rhs) {
  return lhs == rhs;
}

// Runs every registered case; returns the process exit code (0 on success).
int RunAll(int argc, char** argv);

}  // namespace pp_test

#define PP_TEST(suite_name, case_name)                                                             \
  static void suite_name##_##case_name##_body();                                                  \
  static const ::pp_test::Registrar suite_name##_##case_name##_registrar(#suite_name,             \
                                                                        #case_name,                \
                                                                        suite_name##_##case_name##_body); \
  static void suite_name##_##case_name##_body()

#define PP_CHECK(condition)                                                                       \
  do {                                                                                            \
    ::pp_test::g_checks += 1;                                                                     \
    if (!(condition)) {                                                                           \
      ::pp_test::Fail(__FILE__, __LINE__, "check failed: " #condition);                           \
    }                                                                                             \
  } while (false)

#define PP_CHECK_MSG(condition, message)                                                          \
  do {                                                                                            \
    ::pp_test::g_checks += 1;                                                                     \
    if (!(condition)) {                                                                           \
      ::pp_test::Fail(__FILE__, __LINE__, std::string("check failed: " #condition " :: ") + (message)); \
    }                                                                                             \
  } while (false)

#define PP_REQUIRE(condition)                                                                     \
  do {                                                                                            \
    ::pp_test::g_checks += 1;                                                                     \
    if (!(condition)) {                                                                           \
      ::pp_test::Fail(__FILE__, __LINE__, "requirement failed: " #condition);                     \
      return;                                                                                     \
    }                                                                                             \
  } while (false)

// Operands are held by value. Binding them by reference would dangle for expressions such
// as "optional.value()" or "object.Bytes()[i]", which return a reference into a temporary.
#define PP_CHECK_EQ(lhs, rhs)                                                                     \
  do {                                                                                            \
    ::pp_test::g_checks += 1;                                                                     \
    const auto pp_lhs = (lhs);                                                                    \
    const auto pp_rhs = (rhs);                                                                    \
    if (!::pp_test::EqualValues(pp_lhs, pp_rhs)) {                                                \
      ::pp_test::Fail(__FILE__, __LINE__, "equality check failed: " #lhs " == " #rhs);            \
    }                                                                                             \
  } while (false)
