#include "test_framework.hpp"

#include <cstdio>
#include <cstring>
#include <string>

namespace pp_test {

std::uint64_t g_checks = 0;
std::uint64_t g_failures = 0;
std::string g_current;

std::vector<Case>& Registry() {
  static std::vector<Case> registry;
  return registry;
}

Registrar::Registrar(const char* suite, const char* name, std::function<void()> body) {
  Registry().push_back(Case{suite, name, std::move(body)});
}

void Fail(const char* file, int line, const std::string& message) {
  g_failures += 1;
  std::fprintf(stderr, "FAIL %s :: %s:%d :: %s\n", g_current.c_str(), file, line, message.c_str());
  std::fflush(stderr);
  throw Failure{message};
}

int RunAll(int argc, char** argv) {
  const std::string filter = argc > 1 ? argv[1] : std::string();
  std::uint64_t executed = 0;
  std::uint64_t failed_cases = 0;
  for (const Case& test_case : Registry()) {
    if (!filter.empty() && test_case.suite != filter && test_case.name != filter) {
      continue;
    }
    g_current = test_case.suite + "." + test_case.name;
    executed += 1;
    const std::uint64_t failures_before = g_failures;
    try {
      test_case.body();
    } catch (const Failure&) {
      // Recorded by Fail().
    } catch (const std::exception& error) {
      g_failures += 1;
      std::fprintf(stderr, "FAIL %s :: unexpected exception: %s\n", g_current.c_str(), error.what());
    } catch (...) {
      g_failures += 1;
      std::fprintf(stderr, "FAIL %s :: unexpected non-standard exception\n", g_current.c_str());
    }
    if (g_failures != failures_before) {
      failed_cases += 1;
      std::printf("FAILED %s\n", g_current.c_str());
    } else {
      std::printf("ok %s\n", g_current.c_str());
    }
    std::fflush(stdout);
  }
  std::printf("summary cases=%llu failed_cases=%llu checks=%llu failures=%llu\n",
              static_cast<unsigned long long>(executed), static_cast<unsigned long long>(failed_cases),
              static_cast<unsigned long long>(g_checks), static_cast<unsigned long long>(g_failures));
  std::fflush(stdout);
  if (executed == 0) {
    std::fprintf(stderr, "no test cases matched the filter\n");
    return 2;
  }
  return g_failures == 0 ? 0 : 1;
}

}  // namespace pp_test

int main(int argc, char** argv) { return ::pp_test::RunAll(argc, argv); }
