// SPDX-License-Identifier: GPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include "core/hle/service/ns/safe_system_version.h"

TEST_CASE("Safe-system-version check fails closed and retains native cache layout", "[ns]") {
    using namespace Service::NS;
    using namespace std::chrono_literals;
    SafeSystemVersionCache cache;
    const auto start = SafeSystemVersionCache::Clock::time_point{};
    REQUIRE(cache.GetInfo(start) == std::array<u8, 0x20>{});
    REQUIRE(ClassifySafeSystemVersionResponse(404) == ResultSuccess);
    REQUIRE(ClassifySafeSystemVersionResponse(200) == ResultSuccess);
    for (const int status : {0, 301, 403, 500, 503}) {
        REQUIRE(ClassifySafeSystemVersionResponse(status).IsError());
    }
    cache.Update(404, start);
    auto info = cache.GetInfo(start + 3s);
    REQUIRE(info[0] == 3);
    s64 since_check{}, since_safe{};
    std::memcpy(&since_check, info.data() + 8, 8);
    std::memcpy(&since_safe, info.data() + 16, 8);
    REQUIRE(since_check == 3000000000);
    REQUIRE(since_safe == since_check);
    REQUIRE(info[24] == 0);
    cache.Update(0, start + 4s);
    info = cache.GetInfo(start + 5s);
    REQUIRE(info[0] == 1);
    std::memcpy(&since_safe, info.data() + 16, 8);
    REQUIRE(since_safe == 5000000000);
    cache.Update(200, start + 6s);
    info = cache.GetInfo(start + 7s);
    REQUIRE(info[0] == 2);
    REQUIRE_FALSE(cache.last_safe.has_value());
    std::memcpy(&since_safe, info.data() + 16, 8);
    REQUIRE(since_safe == 0);
}
