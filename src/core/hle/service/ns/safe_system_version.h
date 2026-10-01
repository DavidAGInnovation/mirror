// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <chrono>
#include <cstring>
#include <optional>
#include "core/hle/kernel/svc_results.h"
#include "core/hle/result.h"

namespace Service::NS {

// Native NIM treats a missing BVC version entry as safe, and HTTP 200 as
// update-required. Any other response must not grant a safe cache entry.
inline Result ClassifySafeSystemVersionResponse(int status) {
    if (status == 404 || status == 200) {
        return ResultSuccess;
    }
    if (status >= 100 && status <= 599) {
        return Result{ErrorModule::NIM, static_cast<u32>(7000 + status)};
    }
    return Kernel::ResultInvalidState;
}

struct SafeSystemVersionCache {
    using Clock = std::chrono::steady_clock;
    u8 state{}; // Unknown, failed, update-required, safe.
    Clock::time_point checked{};
    std::optional<Clock::time_point> last_safe;

    void Update(int status, Clock::time_point now) {
        state = ClassifySafeSystemVersionResponse(status).IsError() ? 1 : status == 200 ? 2 : 3;
        checked = now;
        if (state == 2) {
            last_safe.reset();
        } else if (state == 3) {
            last_safe = now;
        }
    }

    std::array<u8, 0x20> GetInfo(Clock::time_point now) const {
        std::array<u8, 0x20> info{};
        info[0] = state;
        if (state == 0) {
            return info;
        }
        const auto elapsed = [](auto begin, auto end) -> s64 {
            return std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
        };
        const s64 since_check = elapsed(checked, now);
        std::memcpy(info.data() + 8, &since_check, sizeof(since_check));
        if ((state == 1 || state == 3) && last_safe) {
            const s64 since_safe = elapsed(*last_safe, now);
            std::memcpy(info.data() + 16, &since_safe, sizeof(since_safe));
        }
        return info;
    }
};
} // namespace Service::NS
