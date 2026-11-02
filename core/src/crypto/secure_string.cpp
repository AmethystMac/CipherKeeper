#include "cipherkeeper/crypto/secure_string.hpp"

#include "cipherkeeper/crypto/crypto.hpp"

namespace ck {

bool operator==(const SecureString& a, const SecureString& b) noexcept {
    return crypto::constant_time_equal(a.bytes(), b.bytes());
}

} // namespace ck
