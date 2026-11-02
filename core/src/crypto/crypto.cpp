#include "cipherkeeper/crypto/crypto.hpp"

#include "crypto/crypto_internal.hpp"

#include <sodium.h>

#include <algorithm>
#include <new>
#include <stdexcept>

namespace ck::crypto {

static_assert(key_size == crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
static_assert(key_size == crypto_kdf_hkdf_sha256_KEYBYTES);
static_assert(nonce_size == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
static_assert(tag_size == crypto_aead_xchacha20poly1305_ietf_ABYTES);
static_assert(salt_size == crypto_pwhash_argon2id_SALTBYTES);

namespace {

// Labels for HKDF domain separation. Changing either one changes every derived key, so it needs a vault format bump.
constexpr std::string_view auth_key_label = "cipherkeeper/v1/auth";
constexpr std::string_view kek_label = "cipherkeeper/v1/enc";

// libsodium takes unsigned char pointers; the public API uses std::byte.
const unsigned char* in_ptr(std::span<const std::byte> bytes) noexcept {
    return reinterpret_cast<const unsigned char*>(bytes.data());
}

unsigned char* out_ptr(std::span<std::byte> bytes) noexcept {
    return reinterpret_cast<unsigned char*>(bytes.data());
}

void require_key_size(const SecureBuffer& key) {
    if (key.size() != key_size) {
        throw std::invalid_argument("key must be 32 bytes");
    }
}

void require_valid(const KdfParams& params) {
    if (params.ops_limit < crypto_pwhash_argon2id_OPSLIMIT_MIN ||
        params.ops_limit > crypto_pwhash_argon2id_OPSLIMIT_MAX) {
        throw std::invalid_argument("Argon2id ops_limit is out of range");
    }
    if (params.mem_limit < crypto_pwhash_argon2id_MEMLIMIT_MIN ||
        params.mem_limit > crypto_pwhash_argon2id_MEMLIMIT_MAX) {
        throw std::invalid_argument("Argon2id mem_limit is out of range");
    }
}

} // namespace

namespace detail {

void argon2id(std::span<std::byte> out, std::span<const std::byte> password, std::span<const std::byte, salt_size> salt,
              const KdfParams& params) {
    require_valid(params);
    if (out.size() < crypto_pwhash_argon2id_BYTES_MIN || out.size() > crypto_pwhash_argon2id_BYTES_MAX) {
        throw std::invalid_argument("Argon2id output length is out of range");
    }
    if (password.size() > crypto_pwhash_argon2id_PASSWD_MAX) {
        throw std::invalid_argument("password is too long");
    }
    static constexpr char empty_password = '\0';
    const char* const password_ptr =
        password.empty() ? &empty_password : reinterpret_cast<const char*>(password.data());
    // With the inputs validated above, crypto_pwhash only fails when it can't allocate mem_limit bytes.
    if (crypto_pwhash(out_ptr(out), out.size(), password_ptr, password.size(), in_ptr(salt), params.ops_limit,
                      params.mem_limit, crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::bad_alloc();
    }
}

std::vector<std::byte> seal_with_nonce(const SecureBuffer& key, std::span<const std::byte, nonce_size> nonce,
                                       std::span<const std::byte> plaintext,
                                       std::span<const std::byte> associated_data) {
    require_key_size(key);
    if (plaintext.size() > crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("plaintext is too long");
    }

    std::vector<std::byte> sealed(sealed_overhead + plaintext.size());
    std::ranges::copy(nonce, sealed.begin());
    const std::span<std::byte> body = std::span(sealed).subspan(nonce_size);
    // Encryption can't fail once the lengths are checked, so the return value carries no information.
    (void)crypto_aead_xchacha20poly1305_ietf_encrypt(out_ptr(body), nullptr, in_ptr(plaintext), plaintext.size(),
                                                     in_ptr(associated_data), associated_data.size(), nullptr,
                                                     in_ptr(nonce), in_ptr(key.bytes()));
    return sealed;
}

} // namespace detail

void random_bytes(std::span<std::byte> out) noexcept {
    randombytes_buf(out.data(), out.size());
}

Salt random_salt() {
    Salt salt{};
    random_bytes(salt);
    return salt;
}

SecureBuffer random_key() {
    SecureBuffer key(key_size);
    random_bytes(key.bytes());
    return key;
}

SecureBuffer derive_master_key(const SecureBuffer& password, const Salt& salt, const KdfParams& params) {
    SecureBuffer master_key(key_size);
    detail::argon2id(master_key.bytes(), password.bytes(), salt, params);
    return master_key;
}

SecureBuffer hkdf_expand(const SecureBuffer& prk, std::string_view info, std::size_t size) {
    require_key_size(prk);
    if (size == 0 || size > crypto_kdf_hkdf_sha256_BYTES_MAX) {
        throw std::invalid_argument("HKDF output length is out of range");
    }
    SecureBuffer out(size);
    if (crypto_kdf_hkdf_sha256_expand(out_ptr(out.bytes()), out.size(), info.data(), info.size(),
                                      in_ptr(prk.bytes())) != 0) {
        throw std::invalid_argument("HKDF expansion failed");
    }
    return out;
}

DerivedKeys derive_subkeys(const SecureBuffer& master_key) {
    return {hkdf_expand(master_key, auth_key_label, key_size), hkdf_expand(master_key, kek_label, key_size)};
}

std::vector<std::byte> seal(const SecureBuffer& key, std::span<const std::byte> plaintext,
                            std::span<const std::byte> associated_data) {
    std::array<std::byte, nonce_size> nonce{};
    random_bytes(nonce);
    return detail::seal_with_nonce(key, nonce, plaintext, associated_data);
}

std::optional<SecureBuffer> open(const SecureBuffer& key, std::span<const std::byte> sealed,
                                 std::span<const std::byte> associated_data) {
    require_key_size(key);
    if (sealed.size() < sealed_overhead) {
        return std::nullopt;
    }
    const std::span<const std::byte, nonce_size> nonce = sealed.first<nonce_size>();
    const std::span<const std::byte> body = sealed.subspan(nonce_size);

    SecureBuffer plaintext(body.size() - tag_size);
    // libsodium checks the tag before decrypting anything, so a failed call writes no plaintext.
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(out_ptr(plaintext.bytes()), nullptr, nullptr, in_ptr(body),
                                                   body.size(), in_ptr(associated_data), associated_data.size(),
                                                   in_ptr(nonce), in_ptr(key.bytes())) != 0) {
        return std::nullopt;
    }
    return plaintext;
}

bool constant_time_equal(std::span<const std::byte> a, std::span<const std::byte> b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    return a.empty() || sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace ck::crypto
