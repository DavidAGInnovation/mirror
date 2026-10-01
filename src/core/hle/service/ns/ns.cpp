// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// SPDX-FileCopyrightText: Copyright 2018 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <mutex>
#include <thread>
#include "common/httplib.h"
#include "core/core.h"
#include "core/hle/kernel/k_readable_event.h"
#include "core/hle/kernel/kernel.h"
#include "core/hle/service/kernel_helpers.h"
#include "core/hle/service/ns/safe_system_version.h"
#include "core/hle/service/os/event.h"
#include "core/hle/service/set/system_settings_server.h"
#ifdef YUZU_BUNDLED_OPENSSL
#include <openssl/cert.h>
#endif

#include "core/hle/service/ns/develop_interface.h"
#include "core/hle/service/ns/ns.h"
#include "core/hle/service/ns/platform_service_manager.h"
#include "core/hle/service/ns/query_service.h"
#include "core/hle/service/ns/service_getter_interface.h"
#include "core/hle/service/ns/system_update_interface.h"
#include "core/hle/service/ipc_helpers.h"
#include "core/hle/service/cmif_serialization.h"
#include "core/hle/service/cmif_types.h"
#include "core/hle/service/server_manager.h"

namespace Service::NS {

struct SharedSafeVersionCache {
    std::mutex mutex;
    SafeSystemVersionCache value;
};

class SafeVersionAsyncResult final : public ServiceFramework<SafeVersionAsyncResult> {
public:
    SafeVersionAsyncResult(Core::System& system_, std::shared_ptr<SharedSafeVersionCache> cache_,
                           std::string path_)
        : ServiceFramework{system_, "IAsyncResult"}, context{system_, "SafeVersionCheck"},
          event{context} {
        static const FunctionInfo functions[] = {
            {0, D<&SafeVersionAsyncResult::Get>, "Get"},
            {1, D<&SafeVersionAsyncResult::Cancel>, "Cancel"},
            {2, D<&SafeVersionAsyncResult::GetErrorContext>, "GetErrorContext"},
        };
        RegisterHandlers(functions);
        worker = std::jthread([this, cache = std::move(cache_),
                               path = std::move(path_)](std::stop_token stop) {
            system.Kernel().RegisterHostThread(nullptr);
            httplib::Client client("https://bvc-hac-lp1.cdn.nintendo.net");
            client.enable_server_certificate_verification(true);
            client.enable_server_hostname_verification(true);
            client.set_follow_location(false);
            client.set_connection_timeout(std::chrono::seconds(10));
            client.set_read_timeout(std::chrono::seconds(10));
            client.set_max_timeout(std::chrono::seconds(20));
#ifdef YUZU_BUNDLED_OPENSSL
            client.load_ca_cert_store(kCert, sizeof(kCert));
#endif
            std::stop_callback on_stop(stop, [&client] { client.stop(); });
            const auto response = client.Get(path);
            const int status = response ? response->status : 0;
            const Result check_result = ClassifySafeSystemVersionResponse(status);
            LOG_INFO(Service_NS,
                     "Safe-system-version check: HTTP {}, transport error {}, result {:X}", status,
                     response ? 0 : static_cast<int>(response.error()), check_result.raw);
            std::scoped_lock lock{mutex};
            if (stop.stop_requested() || complete) {
                return;
            }
            {
                std::scoped_lock cache_lock{cache->mutex};
                cache->value.Update(status, SafeSystemVersionCache::Clock::now());
            }
            result = check_result;
            complete = true;
            event.Signal(system.Kernel());
        });
    }

    Kernel::KReadableEvent* GetEvent() {
        return event.GetHandle();
    }

private:
    Result Get() {
        std::scoped_lock lock{mutex};
        return complete ? result : Kernel::ResultInvalidState;
    }
    Result Cancel() {
        worker.request_stop();
        std::scoped_lock lock{mutex};
        if (!complete) {
            complete = true;
            result = Kernel::ResultCancelled;
            event.Signal(system.Kernel());
        }
        R_SUCCEED();
    }
    Result GetErrorContext(OutBuffer<BufferAttr_HipcMapAlias> out_context) {
        // No Nintendo error-context payload is available for this host request.
        std::ranges::fill(out_context, 0);
        R_SUCCEED();
    }
    KernelHelpers::ServiceContext context;
    Event event;
    std::mutex mutex;
    Result result{Kernel::ResultInvalidState};
    bool complete{};
    // Join before destroying the event, its service context, or shared state.
    std::jthread worker;
};

class INotifyService final : public ServiceFramework<INotifyService> {
public:
    explicit INotifyService(Core::System& system_) : ServiceFramework{system_, "pdm:ntfy"} {
        // clang-format off
        static const FunctionInfo functions[] = {
            { 0, nullptr, "NotifyAppletEvent" },
            { 2, nullptr, "NotifyOperationModeChangeEvent" },
            { 3, nullptr, "NotifyPowerStateChangeEvent" },
            { 4, nullptr, "NotifyClearAllEvent" },
            { 5, nullptr, "NotifyEventForDebug" },
            { 6, nullptr, "SuspendUserAccountEventService" },
            { 7, nullptr, "ResumeUserAccountEventService" },
            { 8, nullptr, "NotifyLibraryAppletEvent" },
            { 9, nullptr, "Cmd9" },
            { 20, nullptr, "Cmd20" },
            { 30, nullptr, "Cmd30" },
            { 100, nullptr, "Cmd100" },
            { 101, nullptr, "Cmd101" },
        };
        // clang-format on
        RegisterHandlers(functions);
    }
};

class IVulnerabilityManagerInterface final
    : public ServiceFramework<IVulnerabilityManagerInterface> {
public:
    explicit IVulnerabilityManagerInterface(Core::System& system_)
        : ServiceFramework{system_, "ns:vm"}, cache{std::make_shared<SharedSafeVersionCache>()} {
        // clang-format off
        static const FunctionInfo functions[] = {
            {1200, D<&IVulnerabilityManagerInterface::NeedsUpdateVulnerability>, "NeedsUpdateVulnerability"},
            {1201, nullptr, "UpdateSafeSystemVersionForDebug"},
            {1202, nullptr, "GetSafeSystemVersion"},
            {3100, D<&IVulnerabilityManagerInterface::GetSafeSystemVersionCheckInfo>, "GetSafeSystemVersionCheckInfo"},
            {3101, D<&IVulnerabilityManagerInterface::RequestUpdateSafeSystemVersionCheckInfo>, "RequestUpdateSafeSystemVersionCheckInfo"},
            {3102, D<&IVulnerabilityManagerInterface::ResetSafeSystemVersionCheckInfo>, "ResetSafeSystemVersionCheckInfo"},
        };
        // clang-format on
        RegisterHandlers(functions);
    }
    ~IVulnerabilityManagerInterface() override = default;

    Result NeedsUpdateVulnerability(Out<bool> out_needs_update_vulnerability) {
        LOG_WARNING(Service_NS, "(STUBBED)");
        *out_needs_update_vulnerability = false;
        R_SUCCEED();
    }

    Result GetSafeSystemVersionCheckInfo(Out<std::array<u8, 0x20>> out_system_version_check_info) {
        std::scoped_lock lock{cache->mutex};
        *out_system_version_check_info = cache->value.GetInfo(SafeSystemVersionCache::Clock::now());
        R_SUCCEED();
    }

    Result RequestUpdateSafeSystemVersionCheckInfo(
        Out<std::shared_ptr<SafeVersionAsyncResult>> out_result,
        OutCopyHandle<Kernel::KReadableEvent> out_event) {
        Set::FirmwareVersionFormat firmware{};
        R_TRY(Set::GetFirmwareVersionImpl(firmware, system, Set::GetFirmwareVersionType::Version2));
        auto task = std::make_shared<SafeVersionAsyncResult>(
            system, cache,
            fmt::format("/{}-{}-{}", firmware.major, firmware.minor, firmware.micro));
        *out_event = task->GetEvent();
        *out_result = std::move(task);
        R_SUCCEED();
    }

    Result ResetSafeSystemVersionCheckInfo() {
        std::scoped_lock lock{cache->mutex};
        cache->value = {};
        R_SUCCEED();
    }

private:
    std::shared_ptr<SharedSafeVersionCache> cache;
};

void LoopProcess(Core::System& system) {
    auto server_manager = std::make_unique<ServerManager>(system);

    server_manager->RegisterNamedService("ns:am2", std::make_shared<IServiceGetterInterface>(system, "ns:am2"), 5);
    server_manager->RegisterNamedService("ns:ec", std::make_shared<IServiceGetterInterface>(system, "ns:ec"), 5);
    server_manager->RegisterNamedService("ns:rid", std::make_shared<IServiceGetterInterface>(system, "ns:rid"), 5);
    server_manager->RegisterNamedService("ns:rt", std::make_shared<IServiceGetterInterface>(system, "ns:rt"), 5);
    server_manager->RegisterNamedService("ns:web", std::make_shared<IServiceGetterInterface>(system, "ns:web"), 5);
    server_manager->RegisterNamedService("ns:ro", std::make_shared<IServiceGetterInterface>(system, "ns:ro"), 5);

    server_manager->RegisterNamedService("ns:dev", std::make_shared<IDevelopInterface>(system), 5);
    server_manager->RegisterNamedService("ns:su", std::make_shared<ISystemUpdateInterface>(system), 5);
    server_manager->RegisterNamedService("ns:vm", std::make_shared<IVulnerabilityManagerInterface>(system), 5);
    server_manager->RegisterNamedService("pdm:ntfy", std::make_shared<INotifyService>(system));
    server_manager->RegisterNamedService("pdm:qry", std::make_shared<IQueryService>(system));

    server_manager->RegisterNamedService("pl:s", std::make_shared<IPlatformServiceManager>(system, "pl:s"));
    server_manager->RegisterNamedService("pl:u", std::make_shared<IPlatformServiceManager>(system, "pl:u"));
    ServerManager::RunServer(std::move(server_manager));
}

} // namespace Service::NS
