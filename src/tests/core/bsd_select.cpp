// SPDX-License-Identifier: GPL-3.0-or-later
#include <algorithm>
#include <array>
#include <catch2/catch_test_macros.hpp>
#include "common/scope_exit.h"
#include "common/settings.h"
#include "core/core.h"
#include "core/hle/service/sockets/bsd.h"
#include "core/internal_network/sockets.h"

namespace Service::Sockets {
struct BSDTestAccess {
    static auto Create(BSD_USA& bsd, Type type) {
        return bsd.SocketImpl(Domain::INET, type, Protocol::UDP);
    }
    static auto Flags(BSD_USA& bsd, s32 fd) {
        return bsd.FcntlImpl(fd, FcntlCmd::GETFL, 0);
    }
    static auto Select(BSD_USA& bsd, s32 nfds, const std::array<std::span<const u8>, 3>& in,
                       std::array<std::vector<u8>, 3>& out, s64 sec = 0, s64 usec = 0) {
        return bsd.SelectImpl(nfds, in, out, sec, usec, false);
    }
};
} // namespace Service::Sockets

TEST_CASE("Guest socket flags and select reflect real socket readiness", "[core][network][bsd]") {
    using namespace Service::Sockets;
    Network::NetworkInstance network;
    Core::System system;
    BSD_USA bsd(system, "bsd:test", true);
    const bool airplane = Settings::values.airplane_mode.GetValue();
    Settings::values.airplane_mode.SetValue(false);
    SCOPE_EXIT {
        Settings::values.airplane_mode.SetValue(airplane);
    };
    const auto [fd, error] = BSDTestAccess::Create(bsd, static_cast<Type>(0x30000002));
    REQUIRE(error == Errno::SUCCESS);
    REQUIRE(fd >= 0);
    bool closed{};
    SCOPE_EXIT {
        if (!closed)
            bsd.CloseImpl(fd);
    };
    REQUIRE((BSDTestAccess::Flags(bsd, fd).first & Network::FLAG_O_NONBLOCK) != 0);
    auto receiver = *bsd.GetSocket(fd);
    REQUIRE(receiver->Bind({Network::Domain::INET, {127, 0, 0, 1}, 0}) == Network::Errno::SUCCESS);
    std::array<u8, 8> message{};
    REQUIRE(receiver->Recv(0, message).second == Network::Errno::AGAIN);
    std::array<std::vector<u8>, 3> in, out;
    for (size_t i = 0; i < 3; ++i) {
        in[i].resize(16);
        out[i].resize(16);
    }
    in[0][fd / 8] |= 1U << (fd % 8);
    in[1][fd / 8] |= 1U << (fd % 8);
    const std::array<std::span<const u8>, 3> spans{in[0], in[1], in[2]};
    auto result = BSDTestAccess::Select(bsd, fd + 1, spans, out);
    REQUIRE(result.second == Errno::SUCCESS);
    REQUIRE(result.first == 1);
    REQUIRE(out[0][fd / 8] == 0);
    REQUIRE(out[1][fd / 8] == in[1][fd / 8]);
    Network::Socket sender;
    REQUIRE(sender.Initialize(Network::Domain::INET, Network::Type::DGRAM,
                              Network::Protocol::UDP) == Network::Errno::SUCCESS);
    const auto [address, address_error] = receiver->GetSockName();
    REQUIRE(address_error == Network::Errno::SUCCESS);
    REQUIRE(sender.SendTo(0, std::array<u8, 1>{42}, &address).second == Network::Errno::SUCCESS);
    std::fill(in[1].begin(), in[1].end(), 0);
    result = BSDTestAccess::Select(bsd, fd + 1, spans, out, 1);
    REQUIRE(result.second == Errno::SUCCESS);
    REQUIRE(result.first == 1);
    REQUIRE(out[0][fd / 8] == in[0][fd / 8]);
    REQUIRE(receiver->Recv(0, message).first == 1);
    REQUIRE(message[0] == 42);
    REQUIRE(sender.Connect(address) == Network::Errno::SUCCESS);
    REQUIRE(sender.Send(std::array<u8, 1>{43}, Network::FLAG_MSG_NOSIGNAL).first == 1);
    result = BSDTestAccess::Select(bsd, fd + 1, spans, out, 1);
    REQUIRE(result.second == Errno::SUCCESS);
    REQUIRE(result.first == 1);
    REQUIRE(receiver->Recv(0, message).first == 1);
    REQUIRE(message[0] == 43);
    const auto [rejected_count, rejected_error] = sender.Send(std::array<u8, 1>{44}, 0x40000);
    REQUIRE(rejected_count == -1);
    REQUIRE(rejected_error == Network::Errno::INVAL);

    result = BSDTestAccess::Select(bsd, fd + 1, spans, out);
    REQUIRE(result.first == 0);
    REQUIRE(out[0][fd / 8] == 0);
    REQUIRE(BSDTestAccess::Select(bsd, -1, spans, out).second == Errno::INVAL);
    REQUIRE(BSDTestAccess::Select(bsd, 129, spans, out).second == Errno::INVAL);
    REQUIRE(BSDTestAccess::Select(bsd, fd + 1, spans, out, -1).second == Errno::INVAL);
    REQUIRE(BSDTestAccess::Select(bsd, fd + 1, spans, out, 0, 1'000'000).second == Errno::INVAL);
    REQUIRE(bsd.CloseImpl(fd) == Errno::SUCCESS);
    closed = true;
    REQUIRE(BSDTestAccess::Select(bsd, fd + 1, spans, out).second == Errno::BADF);
}
