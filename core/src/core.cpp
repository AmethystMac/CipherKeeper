#include "cipherkeeper/core.hpp"

#include <sodium.h>
#include <sqlite3.h>

// The key hierarchy needs HKDF-SHA256, which libsodium added in 1.0.19.
#ifndef crypto_kdf_hkdf_sha256_KEYBYTES
#error "libsodium >= 1.0.19 is required (crypto_kdf_hkdf_sha256)"
#endif

namespace ck {

    bool initialize() noexcept {
        // sodium_init() returns 0 on first success, 1 if already initialized, -1 on failure.
        return sodium_init() >= 0;
    }

    std::string_view version() noexcept { return CK_VERSION; }

    LibraryVersions library_versions() noexcept { return {sodium_version_string(), sqlite3_libversion()}; }

} // namespace ck
