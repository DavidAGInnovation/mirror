// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <memory>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include "core/hle/service/ssl/ssl_backend.h"
namespace Service::SSL {
using ImportedCertificate = std::unique_ptr<X509, decltype(&X509_free)>;
using ImportedStore = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
inline ImportedCertificate ParseImportedPki(const ServerPki& cert) {
    ImportedCertificate result{nullptr, X509_free};
    if (cert.data.empty() || cert.data.size() > 65536)
        return result;
    if (cert.format == 2) {
        const auto* cursor = cert.data.data();
        result.reset(d2i_X509(nullptr, &cursor, static_cast<long>(cert.data.size())));
        if (cursor != cert.data.data() + cert.data.size())
            result.reset();
    } else if (cert.format == 1) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio{
            BIO_new_mem_buf(cert.data.data(), static_cast<int>(cert.data.size())), BIO_free};
        if (bio)
            result.reset(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    }
    return result;
}
inline ImportedStore BuildImportedPkiStore(std::span<const ServerPki> certificates) {
    ImportedStore store{X509_STORE_new(), X509_STORE_free};
    if (!store)
        return store;
    for (const auto& input : certificates) {
        auto cert = ParseImportedPki(input);
        if (!cert || !X509_STORE_add_cert(store.get(), cert.get())) {
            store.reset();
            break;
        }
    }
    return store;
}
} // namespace Service::SSL
