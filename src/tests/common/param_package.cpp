// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// SPDX-FileCopyrightText: 2017 Citra Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <cerrno>
#include <cmath>
#include <limits>
#include <catch2/catch_test_macros.hpp>
#include <math.h>
#include "common/logging.h"
#include "common/param_package.h"

namespace Common {

TEST_CASE("ParamPackage", "[common]") {
    ParamPackage original{
        {"abc", "xyz"},
        {"def", "42"},
        {"jkl", "$$:1:$2$,3"},
    };
    original.Set("ghi", 3.14f);
    ParamPackage copy(original.Serialize());
    REQUIRE(copy.Get("abc", "") == "xyz");
    REQUIRE(copy.Get("def", 0) == 42);
    REQUIRE(std::abs(copy.Get("ghi", 0.0f) - 3.14f) < 0.01f);
    REQUIRE(copy.Get("jkl", "") == "$$:1:$2$,3");
    REQUIRE(copy.Get("mno", "uvw") == "uvw");
    REQUIRE(copy.Get("abc", 42) == 42);
}

TEST_CASE("ParamPackage numeric conversion preserves fallback behavior", "[common]") {
    ParamPackage package{{"empty", ""},
                         {"text", "xyz"},
                         {"integer", "  +42tail"},
                         {"minimum", std::to_string(std::numeric_limits<int>::min())},
                         {"maximum", std::to_string(std::numeric_limits<int>::max())},
                         {"overflow", "999999999999999999999999999999999"},
                         {"float", "  -3.5tail"},
                         {"float_overflow", "1e9999"},
                         {"float_underflow", "1e-9999"},
                         {"hex_float", "0x1p+2"},
                         {"infinity", "inf"},
                         {"nan", "nan"}};
    REQUIRE(package.Get("empty", 42) == 42);
    REQUIRE(package.Get("text", 42) == 42);
    REQUIRE(package.Get("overflow", 42) == 42);
    REQUIRE(package.Get("minimum", 0) == std::numeric_limits<int>::min());
    REQUIRE(package.Get("maximum", 0) == std::numeric_limits<int>::max());
    REQUIRE(package.Get("integer", 0) == 42);
    REQUIRE(package.Get("empty", 2.0f) == 2.0f);
    REQUIRE(package.Get("text", 2.0f) == 2.0f);
    REQUIRE(package.Get("float_overflow", 2.0f) == 2.0f);
    REQUIRE(package.Get("float_underflow", 2.0f) == 2.0f);
    REQUIRE(package.Get("float", 0.0f) == -3.5f);
    REQUIRE(package.Get("hex_float", 0.0f) == 4.0f);
    REQUIRE(std::isinf(package.Get("infinity", 0.0f)));
    REQUIRE(std::isnan(package.Get("nan", 0.0f)));
    const int previous_errno = errno;
    errno = EDOM;
    const int fallback = package.Get("overflow", 42);
    const int preserved_errno = errno;
    errno = previous_errno;
    REQUIRE(fallback == 42);
    REQUIRE(preserved_errno == EDOM);
}

} // namespace Common
