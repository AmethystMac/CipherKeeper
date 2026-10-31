#pragma once

// Lower-level entry points that the public API builds on. They are exposed only so known-answer tests can drive
// libsodium with fixed vectors. Production code must use crypto.hpp: a caller-chosen nonce is how nonce reuse
// happens.

#include "cipherkeeper/crypto.hpp"

#include <span>
#include <vector>

namespace ck::crypto::detail {

// Argon2id with an arbitrary output length, writing out.size() bytes.
void argon2id(std::span<std::byte> out, std::span<const std::byte> password, std::span<const std::byte, salt_size> salt,
              const KdfParams& params);

// seal() with a caller-supplied nonce. Output layout is the same: nonce || ciphertext || tag.
[[nodiscard]] std::vector<std::byte> seal_with_nonce(const SecureBuffer& key,
                                                     std::span<const std::byte, nonce_size> nonce,
                                                     std::span<const std::byte> plaintext,
                                                     std::span<const std::byte> associated_data);

} // namespace ck::crypto::detail
