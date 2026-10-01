// SPDX-License-Identifier: GPL-3.0-or-later

#include <array>
#include <atomic>
#include <chrono>
#include <future>
#include <thread>
#include <catch2/catch_test_macros.hpp>

#include "common/scope_exit.h"
#include "common/settings.h"
#include "core/core.h"
#include "core/core_timing.h"
#include "core/device_memory.h"
#include "core/file_sys/program_metadata.h"
#include "core/hle/kernel/board/nintendo/nx/k_system_control.h"
#include "core/hle/kernel/k_light_lock.h"
#include "core/hle/kernel/k_memory_layout.h"
#include "core/hle/kernel/k_memory_manager.h"
#include "core/hle/kernel/k_object_name.h"
#include "core/hle/kernel/k_process.h"
#include "core/hle/kernel/k_resource_limit.h"
#include "core/hle/kernel/k_system_resource.h"
#include "core/hle/kernel/kernel.h"
#include "core/hle/kernel/svc.h"
#include "core/hle/kernel/svc_results.h"

namespace {
using Kernel::Board::Nintendo::Nx::KSystemControl;
constexpr auto Pool = static_cast<u32>(Kernel::KMemoryManager::Pool::Applet);

struct KernelFixture {
    Core::System system;
    const bool previous_debug_asserts = Settings::values.use_debug_asserts.GetValue();
    KernelFixture() {
        Settings::values.use_debug_asserts.SetValue(true);
        system.Initialize();
        system.Kernel().Initialize();
    }
    ~KernelFixture() {
        system.CoreTiming().SyncPause(true);
        system.CoreTiming().ClearPendingEvents();
        system.Kernel().Shutdown();
        Settings::values.use_debug_asserts.SetValue(previous_debug_asserts);
    }
};
} // namespace

TEST_CASE("Firmware 23 memory info queries validate handles and disabled shadow stacks",
          "[kernel]") {
    KernelFixture fixture;
    auto& kernel = fixture.system.Kernel();
    auto* process = Kernel::KProcess::Create(kernel);
    REQUIRE(process != nullptr);
    SCOPE_EXIT {
        process->Close(kernel);
    };
    REQUIRE(process->LoadFromMetadata(kernel, FileSys::ProgramMetadata::GetDefault(), 0x1000, 0,
                                      0) == ResultSuccess);
    REQUIRE(process->GetHandleTable().Initialize(kernel, 16) == ResultSuccess);
    SCOPE_EXIT {
        process->GetHandleTable().Finalize(kernel);
    };
    auto* thread = Kernel::KThread::Create(kernel);
    REQUIRE(thread != nullptr);
    REQUIRE(process->GetResourceLimit()->Reserve(
        kernel, Kernel::Svc::LimitableResource::ThreadCountMax, 1));
    REQUIRE(Kernel::KThread::InitializeDummyThread(fixture.system, thread, process) ==
            ResultSuccess);
    auto* previous_thread = kernel.GetCurrentEmuThread();
    kernel.SetCurrentEmuThread(thread);
    SCOPE_EXIT {
        kernel.SetCurrentEmuThread(previous_thread);
        thread->Close(kernel);
    };

    using Kernel::Svc::InfoType;
    constexpr auto CurrentProcess = Kernel::Svc::PseudoHandle::CurrentProcess;
    for (const auto type : {InfoType::AddressSpaceSize, InfoType::ShadowStackRegionAddress,
                            InfoType::ShadowStackRegionSize}) {
        u64 value = 0xdeadbeef;
        REQUIRE(Kernel::Svc::GetInfo(fixture.system, &value, type, 0, 0) ==
                Kernel::ResultInvalidHandle);
        REQUIRE(value == 0xdeadbeef);
        REQUIRE(Kernel::Svc::GetInfo(fixture.system, &value, type, CurrentProcess, 1) ==
                Kernel::ResultInvalidCombination);
        REQUIRE(value == 0xdeadbeef);
        REQUIRE(Kernel::Svc::GetInfo(fixture.system, &value, type, CurrentProcess, 0) ==
                ResultSuccess);
        REQUIRE(value == (type == InfoType::AddressSpaceSize ? (1ULL << 39) : 0));
    }
}

TEST_CASE("Secure applet memory uses its reserved region and can be reused", "[kernel]") {
    KernelFixture fixture;
    auto& kernel = fixture.system.Kernel();
    constexpr size_t Size = 0x20000;
    Kernel::KVirtualAddress address{0xdead0000};
    REQUIRE(KSystemControl::AllocateSecureMemory(kernel, &address, Size + 1, Pool) ==
            Kernel::ResultInvalidSize);
    REQUIRE(GetInteger(address) == 0xdead0000);
    REQUIRE(KSystemControl::AllocateSecureMemory(kernel, &address,
                                                 KSystemControl::SecureAppletMemorySize + 0x1000,
                                                 Pool) == Kernel::ResultOutOfMemory);
    REQUIRE(GetInteger(address) == 0xdead0000);
    REQUIRE(KSystemControl::CalculateRequiredSecureMemorySize(Size, Pool) == 0);
    const auto* physical_slab =
        kernel.MemoryLayout().GetPhysicalMemoryRegionTree().FindFirstDerived(
            Kernel::KMemoryRegionType_DramKernelSlab);
    REQUIRE(physical_slab != nullptr);
    // Slab backing must occupy its reserved physical region, not the obsolete
    // fixed offset, which can overlap the neighboring secure carveout.
    for (const auto slab_address : {Kernel::KResourceLimit::GetSlabHeapAddress(kernel),
                                    Kernel::KProcess::GetSlabHeapAddress(kernel),
                                    Kernel::KObjectName::GetSlabHeapAddress(kernel)}) {
        const auto physical = GetInteger(fixture.system.DeviceMemory().GetPhysicalAddr(
            reinterpret_cast<const u8*>(slab_address)));
        REQUIRE(physical >= physical_slab->GetAddress());
        REQUIRE(physical < physical_slab->GetEndAddress());
    }
    const auto event_limit = kernel.GetSystemResourceLimit()->GetLimitValue(
        Kernel::Svc::LimitableResource::EventCountMax);
    REQUIRE(KSystemControl::AllocateSecureMemory(kernel, &address, Size, Pool) == ResultSuccess);

    const auto* region = kernel.MemoryLayout().GetPhysicalMemoryRegionTree().FindFirstDerived(
        Kernel::KMemoryRegionType_DramKernelSecureAppletMemory);
    REQUIRE(region != nullptr);
    REQUIRE(GetInteger(address) == region->GetPairAddress());
    auto* backing = fixture.system.DeviceMemory().GetPointer<u8>(region->GetAddress());
    REQUIRE(backing[0] == 0);
    backing[0] = 0x42;

    Kernel::KVirtualAddress second{0};
    REQUIRE(KSystemControl::AllocateSecureMemory(kernel, &second, Size, Pool) ==
            Kernel::ResultOutOfMemory);
    REQUIRE(second == 0);
    REQUIRE(backing[0] == 0x42);
    KSystemControl::FreeSecureMemory(kernel, address, Size, Pool);
    REQUIRE(KSystemControl::AllocateSecureMemory(
                kernel, &second, KSystemControl::SecureAppletMemorySize, Pool) == ResultSuccess);
    REQUIRE(second == address);
    REQUIRE(backing[0] == 0);
    REQUIRE(kernel.GetSystemResourceLimit()->GetLimitValue(
                Kernel::Svc::LimitableResource::EventCountMax) == event_limit);
    KSystemControl::FreeSecureMemory(kernel, second, KSystemControl::SecureAppletMemorySize, Pool);
}

TEST_CASE("Concurrent secure applet allocations grant exactly one lease", "[kernel]") {
    KernelFixture fixture;
    auto& kernel = fixture.system.Kernel();
    constexpr size_t Size = 0x20000;
    std::array<Result, 8> results{};
    std::array<Kernel::KVirtualAddress, 8> addresses{};
    std::array<std::thread, 8> threads;
    for (size_t i = 0; i < threads.size(); ++i) {
        threads[i] = std::thread([&, i] {
            results[i] = KSystemControl::AllocateSecureMemory(kernel, &addresses[i], Size, Pool);
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    size_t successes = 0;
    for (size_t i = 0; i < results.size(); ++i) {
        if (results[i] == ResultSuccess) {
            ++successes;
            KSystemControl::FreeSecureMemory(kernel, addresses[i], Size, Pool);
        } else {
            REQUIRE(results[i] == Kernel::ResultOutOfMemory);
        }
    }
    REQUIRE(successes == 1);
}

TEST_CASE("Applet system resources release their secure carveout on finalization", "[kernel]") {
    KernelFixture fixture;
    auto& kernel = fixture.system.Kernel();
    Kernel::KSecureSystemResource first{kernel};
    Kernel::KSecureSystemResource second{kernel};
    constexpr auto AppletPool = Kernel::KMemoryManager::Pool::Applet;
    constexpr size_t Size = 0x20000;

    // Failure after obtaining the lease must release it for the next resource.
    REQUIRE(first.Initialize(kernel, 0x1000, kernel.GetSystemResourceLimit(), AppletPool) ==
            Kernel::ResultOutOfMemory);
    REQUIRE(first.Initialize(kernel, Size, kernel.GetSystemResourceLimit(), AppletPool) ==
            ResultSuccess);
    REQUIRE(second.Initialize(kernel, Size, kernel.GetSystemResourceLimit(), AppletPool) ==
            Kernel::ResultOutOfMemory);
    first.Finalize(kernel);
    REQUIRE(second.Initialize(kernel, Size, kernel.GetSystemResourceLimit(), AppletPool) ==
            ResultSuccess);
    second.Finalize(kernel);
}

TEST_CASE("Contended light locks keep host waiter queues alive until ownership transfers",
          "[kernel][light-lock]") {
    KernelFixture fixture;
    auto& kernel = fixture.system.Kernel();
    Kernel::KLightLock lock{kernel};
    for (int round = 0; round < 50; ++round) {
        lock.Lock();
        std::promise<Kernel::KThread*> ready;
        auto ready_future = ready.get_future();
        std::atomic_bool acquired = false;
        std::atomic_bool owned = false;
        std::thread waiter([&] {
            ready.set_value(kernel.GetCurrentEmuThread());
            lock.Lock();
            owned = lock.IsLockedByCurrentThread();
            acquired = true;
            lock.Unlock();
        });
        auto* thread = ready_future.get();
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (thread->GetState() != Kernel::ThreadState::Waiting &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::yield();
        }
        const bool waiting = thread->GetState() == Kernel::ThreadState::Waiting;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        const bool returned_early = acquired.load();
        lock.Unlock();
        waiter.join();
        REQUIRE(waiting);
        REQUIRE_FALSE(returned_early);
        REQUIRE(owned.load());
        REQUIRE(acquired.load());
    }
}

TEST_CASE("Cancelled light lock waiters reacquire ownership before returning",
          "[kernel][light-lock]") {
    KernelFixture fixture;
    auto& kernel = fixture.system.Kernel();
    Kernel::KLightLock lock{kernel};
    lock.Lock();
    std::promise<Kernel::KThread*> ready;
    auto ready_future = ready.get_future();
    std::atomic_bool acquired = false;
    std::atomic_bool owned = false;
    std::thread waiter([&] {
        ready.set_value(kernel.GetCurrentEmuThread());
        lock.Lock();
        const bool has_lock = lock.IsLockedByCurrentThread();
        owned = has_lock;
        acquired = true;
        // Avoid corrupting the owner's lock when checking the old implementation.
        if (has_lock)
            lock.Unlock();
    });
    auto* thread = ready_future.get();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (thread->GetState() != Kernel::ThreadState::Waiting &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }
    const bool waiting = thread->GetState() == Kernel::ThreadState::Waiting;
    if (waiting)
        thread->CancelWait(kernel, Kernel::ResultTerminationRequested, true);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    const bool returned_early = acquired.load();
    lock.Unlock();
    waiter.join();
    REQUIRE(waiting);
    REQUIRE_FALSE(returned_early);
    REQUIRE(owned.load());
    REQUIRE(acquired.load());
}

TEST_CASE("Terminated thread cleanup waits for the process list without holding the scheduler",
          "[kernel][light-lock]") {
    KernelFixture fixture;
    auto& kernel = fixture.system.Kernel();
    auto* process = Kernel::KProcess::Create(kernel);
    REQUIRE(process != nullptr);
    SCOPE_EXIT {
        process->Close(kernel);
    };
    REQUIRE(process->LoadFromMetadata(kernel, FileSys::ProgramMetadata::GetDefault(), 0x1000, 0,
                                      0) == ResultSuccess);
    auto* thread = Kernel::KThread::Create(kernel);
    REQUIRE(thread != nullptr);
    REQUIRE(process->GetResourceLimit()->Reserve(
        kernel, Kernel::Svc::LimitableResource::ThreadCountMax, 1));
    REQUIRE(Kernel::KThread::InitializeDummyThread(fixture.system, thread, process) ==
            ResultSuccess);

    process->GetListLock().Lock();
    std::promise<Kernel::KThread*> ready;
    auto ready_future = ready.get_future();
    std::atomic_bool completed = false;
    std::thread finalizer([&] {
        ready.set_value(kernel.GetCurrentEmuThread());
        thread->DoWorkerTask(kernel);
        completed = true;
    });
    auto* finalizer_thread = ready_future.get();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (finalizer_thread->GetState() != Kernel::ThreadState::Waiting &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }
    const bool waiting = finalizer_thread->GetState() == Kernel::ThreadState::Waiting;
    const bool returned_early = completed.load();
    // This requires the scheduler lock, and must work while cleanup is waiting.
    const bool still_owned = process->GetListLock().IsLockedByCurrentThread();
    process->GetListLock().Unlock();
    finalizer.join();
    REQUIRE(waiting);
    REQUIRE_FALSE(returned_early);
    REQUIRE(still_owned);
    REQUIRE(completed.load());
    REQUIRE(process->GetThreadList().empty());
}
