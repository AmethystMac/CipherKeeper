#pragma once

#include "cipherkeeper/secure_buffer.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

// Thin, misuse-resistant wrappers over libsodium. Nothing here implements a primitive.
//
// Functions throw std::invalid_argument for wrong key sizes or out-of-range parameters, and std::bad_alloc when
// memory runs out. A failed authentication check is an expected outcome, not an error, so open() returns
// std::nullopt instead of throwing. Error messages never contain secret material.
namespace ck::crypto {

inline constexpr std::size_t key_size = 32;   // XChaCha20-Poly1305 keys, the master key and every subkey
inline constexpr std::size_t salt_size = 16;  // Argon2id salt (crypto_pwhash_SALTBYTES)
inline constexpr std::size_t nonce_size = 24; // XChaCha20-Poly1305 nonce
inline constexpr std::size_t tag_size = 16;   // Poly1305 tag
inline constexpr std::size_t sealed_overhead = nonce_size + tag_size;

using Salt = std::array<std::byte, salt_size>;

// Argon2id (v1.3) cost parameters, stored with the vault so they can be raised later.
// A default-constructed KdfParams holds the defaults: 64 MiB of memory and 3 passes. libsodium's Argon2id always
// uses a single lane (p = 1), so there is no parallelism setting.
struct KdfParams {
    std::uint64_t ops_limit = 3;                    // passes over memory (t)
    std::size_t mem_limit = std::size_t{64} << 20U; // bytes (m)

    friend bool operator==(const KdfParams&, const KdfParams&) = default;
};

// The two independent keys split from the master key.
struct DerivedKeys {
    SecureBuffer auth_key; // sent to the server to prove the password; useless for decryption
    SecureBuffer kek;      // key-encryption key: wraps the Account Key and the Local Vault Key
};

// Fills `out` from the OS CSPRNG (randombytes_buf).
void random_bytes(std::span<std::byte> out) noexcept;
[[nodiscard]] Salt random_salt();
// A fresh random 32-byte key, e.g. a new Account Key or Local Vault Key.
[[nodiscard]] SecureBuffer random_key();

// Argon2id(password, salt, params) -> 32-byte master key (crypto_pwhash with crypto_pwhash_ALG_ARGON2ID13).
// Throws std::invalid_argument if params are outside libsodium's limits.
[[nodiscard]] SecureBuffer derive_master_key(const SecureBuffer& password, const Salt& salt, const KdfParams& params);

// HKDF-SHA256 expand (RFC 5869 §2.3) of a 32-byte pseudorandom key (crypto_kdf_hkdf_sha256_expand).
// `info` is the domain-separation label. `size` must be between 1 and 255 * 32 bytes.
[[nodiscard]] SecureBuffer hkdf_expand(const SecureBuffer& prk, std::string_view info, std::size_t size);

// Splits the master key into the Auth Key and the KEK with HKDF-Expand under different labels.
// Argon2id output is already uniformly random, so HKDF-Extract is skipped (RFC 5869 §3.3).
[[nodiscard]] DerivedKeys derive_subkeys(const SecureBuffer& master_key);

// XChaCha20-Poly1305 with a fresh random nonce on every call. The output is nonce || ciphertext || tag.
// `associated_data` is authenticated but not encrypted; it binds the ciphertext to its context
// (e.g. item_id | vault_id | schema_version) so it can't be moved to another slot.
[[nodiscard]] std::vector<std::byte> seal(const SecureBuffer& key, std::span<const std::byte> plaintext,
                                          std::span<const std::byte> associated_data);

// Reverses seal(). Returns std::nullopt if the key or associated data is wrong, or if `sealed` was tampered with
// or truncated. No plaintext is ever released from a failed check.
[[nodiscard]] std::optional<SecureBuffer> open(const SecureBuffer& key, std::span<const std::byte> sealed,
                                               std::span<const std::byte> associated_data);

// Constant-time comparison (sodium_memcmp). Inputs of different lengths compare unequal; the lengths themselves
// are not treated as secret.
[[nodiscard]] bool constant_time_equal(std::span<const std::byte> a, std::span<const std::byte> b) noexcept;

} // namespace ck::crypto
