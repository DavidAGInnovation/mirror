// SPDX-License-Identifier: GPL-3.0-or-later
#include <catch2/catch_test_macros.hpp>
#include <openssl/x509v3.h>
#include "core/hle/service/ssl/imported_pki.h"
namespace {
constexpr char certificate[] = R"PEM(-----BEGIN CERTIFICATE-----
MIIBsTCCAVegAwIBAgIUWx4H63itclFb5RRVUtLFaRfNQd0wCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTbmF0aXZlLXRlc3QuaW52YWxpZDAeFw0yNjEwMDExNTQ1MjNa
Fw0zNjA5MjgxNTQ1MjNaMB4xHDAaBgNVBAMME25hdGl2ZS10ZXN0LmludmFsaWQw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASkac7+Gg67Go6TwgHCEJG+dDEgeF6J
3bHEnMrc49PdU3V4GlTto/OSpXCA0umLoZ+pjoqPl8D+ceKq0Lyn4lbpo3MwcTAd
BgNVHQ4EFgQUV4X8H5d19ldvFG1r+immnSrVC2QwHwYDVR0jBBgwFoAUV4X8H5d1
9ldvFG1r+immnSrVC2QwDwYDVR0TAQH/BAUwAwEB/zAeBgNVHREEFzAVghNuYXRp
dmUtdGVzdC5pbnZhbGlkMAoGCCqGSM49BAMCA0gAMEUCICp4wThzziDxM08ZXmmy
j0gvsXAX35LlkBEupEM6euB/AiEA2fUHqgK95I9ae1qYR2+FI/ReLEteUOTK/3N4
uw4HRUA=
-----END CERTIFICATE-----
)PEM";
int Verify(X509_STORE* store, X509* cert, const char* host) {
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> ctx{X509_STORE_CTX_new(),
                                                                        X509_STORE_CTX_free};
    if (!ctx || !X509_STORE_CTX_init(ctx.get(), store, cert, nullptr))
        return 0;
    X509_VERIFY_PARAM_set_time(X509_STORE_CTX_get0_param(ctx.get()), 1800000000);
    X509_VERIFY_PARAM_set1_host(X509_STORE_CTX_get0_param(ctx.get()), host, 0);
    return X509_verify_cert(ctx.get());
}
} // namespace
TEST_CASE("Imported roots stay isolated and hostname verification remains active", "[ssl]") {
    using namespace Service::SSL;
    const ServerPki pem{1, {certificate, certificate + sizeof(certificate) - 1}};
    auto cert = ParseImportedPki(pem);
    REQUIRE(cert);
    auto imported = BuildImportedPkiStore(std::span{&pem, 1});
    auto isolated = BuildImportedPkiStore({});
    REQUIRE(imported);
    REQUIRE(isolated);
    CHECK(Verify(imported.get(), cert.get(), "native-test.invalid") == 1);
    CHECK(Verify(isolated.get(), cert.get(), "native-test.invalid") == 0);
    CHECK(Verify(imported.get(), cert.get(), "wrong.invalid") == 0);
    ServerPki der{2, std::vector<u8>(i2d_X509(cert.get(), nullptr))};
    auto* cursor = der.data.data();
    REQUIRE(i2d_X509(cert.get(), &cursor) > 0);
    CHECK(ParseImportedPki(der));
    der.data.push_back(0);
    CHECK_FALSE(ParseImportedPki(der));
    CHECK_FALSE(ParseImportedPki({2, {1, 2, 3}}));
    CHECK_FALSE(ParseImportedPki({1, {1, 2, 3}}));
    CHECK_FALSE(ParseImportedPki({3, pem.data}));
    CHECK_FALSE(ParseImportedPki({2, std::vector<u8>(65537)}));
    const ServerPki malformed{2, {1, 2, 3}};
    CHECK_FALSE(BuildImportedPkiStore(std::span{&malformed, 1}));
}
