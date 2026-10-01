// SPDX-License-Identifier: GPL-3.0-or-later

#include <array>
#include <cstring>
#include <catch2/catch_test_macros.hpp>
#include "core/file_sys/vfs/vfs_vector.h"
#include "core/hle/service/ssl/cert_store.h"

TEST_CASE("Firmware certificate selectors retain trust and aligned data", "[ssl]") {
    using namespace Service::SSL;
    const CertStoreHeader header{0x546c7373, 3};
    const std::array entries{
        CertStoreEntry{CaCertificateId::GTSRootR1, TrustedCertStatus::EnabledTrusted, 3, 48},
        CertStoreEntry{static_cast<CaCertificateId>(32801), TrustedCertStatus::EnabledNotTrusted, 4,
                       51},
        CertStoreEntry{static_cast<CaCertificateId>(0x7001), TrustedCertStatus::EnabledTrusted, 3,
                       55},
    };
    std::vector<u8> data(sizeof(header) + sizeof(entries) + 10);
    std::memcpy(data.data(), &header, sizeof(header));
    std::memcpy(data.data() + sizeof(header), entries.data(), sizeof(entries));
    const std::array<u8, 10> cert_data{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    std::memcpy(data.data() + 56, cert_data.data(), cert_data.size());
    CertStore store{std::make_shared<FileSys::VectorVfsFile>(data)};
    u32 size{}, count{};
    const std::array all{CaCertificateId::All};
    REQUIRE(store.GetCertificateBufSize(&size, &count, all) == ResultSuccess);
    REQUIRE(count == 1);
    REQUIRE(size == 52);
    store.SetInterfaceVersion(5);
    REQUIRE(store.GetCertificateBufSize(&size, &count, all) == ResultSuccess);
    REQUIRE(count == 3);
    std::vector<u8> all_output(size);
    REQUIRE(store.GetCertificates(&count, all_output, all) == ResultSuccess);
    std::array<BuiltInCertificateInfo, 4> all_info{};
    std::memcpy(all_info.data(), all_output.data(), sizeof(all_info));
    REQUIRE(all_info[2].cert_id == static_cast<CaCertificateId>(0x8021));
    REQUIRE(all_info[2].status == TrustedCertStatus::EnabledNotTrusted);
    const std::array inclusive{CaCertificateId::AllExcludingSystem};
    REQUIRE(store.GetCertificateBufSize(&size, &count, inclusive) == ResultSuccess);
    REQUIRE(count == 2);
    const std::array first_all{CaCertificateId::All, CaCertificateId::AllExcludingSystem};
    REQUIRE(store.GetCertificateBufSize(&size, &count, first_all) == ResultSuccess);
    REQUIRE(count == 3);
    const std::array first_public{CaCertificateId::AllExcludingSystem, CaCertificateId::All};
    REQUIRE(store.GetCertificateBufSize(&size, &count, first_public) == ResultSuccess);
    REQUIRE(count == 2);
    std::vector<u8> output(size, 0xff);
    REQUIRE(store.GetCertificates(&count, output, inclusive) == ResultSuccess);
    std::array<BuiltInCertificateInfo, 3> info{};
    std::memcpy(info.data(), output.data(), sizeof(info));
    REQUIRE(info[0].status == TrustedCertStatus::EnabledTrusted);
    REQUIRE(info[1].status == TrustedCertStatus::EnabledTrusted);
    REQUIRE(info[0].der_offset == 72);
    REQUIRE(info[1].der_offset == 76);
    REQUIRE(output[75] == 0);
    REQUIRE(output[78] == 10);
    REQUIRE(info[2].cert_id == CaCertificateId::All);
    REQUIRE(store.GetCertificates(&count, std::span(output).first(size - 1), inclusive) !=
            ResultSuccess);
    data.resize(57);
    CertStore truncated{std::make_shared<FileSys::VectorVfsFile>(data)};
    REQUIRE(truncated.GetCertificateBufSize(&size, &count, inclusive) == ResultSuccess);
    REQUIRE(count == 0);
    REQUIRE(size == sizeof(BuiltInCertificateInfo));
}
