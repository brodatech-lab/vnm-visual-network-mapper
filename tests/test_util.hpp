#pragma once

#include <cstdio>

namespace vnmtest {

inline int g_failures = 0;
inline int g_checks = 0;

inline void check(bool condition, const char* expr, const char* file, int line) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::fprintf(stderr, "FAIL %s:%d: %s\n", file, line, expr);
    }
}

inline int summary(const char* suite) {
    std::fprintf(stderr, "[%s] %d checks, %d failures\n", suite, g_checks,
                 g_failures);
    return g_failures == 0 ? 0 : 1;
}

} // namespace vnmtest

#define CHECK(cond) ::vnmtest::check((cond), #cond, __FILE__, __LINE__)
