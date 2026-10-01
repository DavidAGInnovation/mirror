// SPDX-FileCopyrightText: Copyright 2021 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <catch2/catch_test_macros.hpp>

#include "core/internal_network/network.h"
#include "core/internal_network/sockets.h"

TEST_CASE("Network::Errors", "[core]") {
    Network::NetworkInstance network_instance; // initialize network

    Network::Socket socks[2];
    for (Network::Socket& sock : socks) {
        REQUIRE(sock.Initialize(Network::Domain::INET, Network::Type::STREAM,
                                Network::Protocol::TCP) == Network::Errno::SUCCESS);
    }

    Network::SockAddrIn addr{
        Network::Domain::INET,
        {127, 0, 0, 1},
        1, // hopefully nobody running this test has something listening on port 1
    };
    REQUIRE(socks[0].Connect(addr) == Network::Errno::CONNREFUSED);

    std::vector<u8> message{1, 2, 3, 4};
    REQUIRE(socks[1].Recv(0, message).second == Network::Errno::NOTCONN);
}

#ifdef __APPLE__
#include <algorithm>
#include <ifaddrs.h>
#include <net/if.h>
#include "common/scope_exit.h"
#include "common/settings.h"
#include "core/internal_network/network_interface.h"

TEST_CASE("macOS network adapters reflect host IPv4 interfaces", "[core][network]") {
    ifaddrs* addresses{};
    REQUIRE(getifaddrs(&addresses) == 0);
    SCOPE_EXIT {
        freeifaddrs(addresses);
    };
    const auto interfaces = Network::GetAvailableNetworkInterfaces();
    size_t expected{};
    for (auto* address = addresses; address; address = address->ifa_next) {
        if (!address->ifa_addr || !address->ifa_netmask ||
            address->ifa_addr->sa_family != AF_INET || !(address->ifa_flags & IFF_UP) ||
            (address->ifa_flags & IFF_LOOPBACK)) {
            continue;
        }
        ++expected;
        const auto match = std::ranges::find_if(interfaces, [&](const auto& adapter) {
            return adapter.name == address->ifa_name &&
                   adapter.ip_address.s_addr ==
                       reinterpret_cast<const sockaddr_in*>(address->ifa_addr)->sin_addr.s_addr &&
                   adapter.subnet_mask.s_addr ==
                       reinterpret_cast<const sockaddr_in*>(address->ifa_netmask)->sin_addr.s_addr;
        });
        REQUIRE(match != interfaces.end());
    }
    REQUIRE(interfaces.size() == expected);
    const auto saved_interface = Settings::values.network_interface.GetValue();
    SCOPE_EXIT {
        Settings::values.network_interface.SetValue(saved_interface);
    };
    Settings::values.network_interface.SetValue("eden-test-nonexistent-interface");
    REQUIRE_FALSE(Network::GetSelectedNetworkInterface().has_value());
    if (!interfaces.empty()) {
        Settings::values.network_interface.SetValue(interfaces.front().name);
        REQUIRE(Network::GetSelectedNetworkInterface().has_value());
        REQUIRE(Network::GetHostIPv4Address().has_value());
    }
}
#endif
