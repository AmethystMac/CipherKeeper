#pragma once

#include "cipherkeeper/crypto/crypto.hpp"
#include "cipherkeeper/crypto/secure_buffer.hpp"
#include "cipherkeeper/model/item_id.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace ck {

// Thrown for problems with the vault file itself. A wrong master password is not an error: Vault::open returns
// std::nullopt instead. Messages never contain secrets or item contents.
class VaultError : public std::runtime_error {
  public:
    enum class Kind : std::uint8_t {
        not_a_vault,         // not a SQLite file, or a SQLite file that isn't a CipherKeeper vault
        unsupported_version, // a vault format this build can't read (e.g. written by a newer version)
        corrupt,             // a vault whose structure or contents fail validation or authentication
        already_exists,      // create() was pointed at an existing, non-empty file
        item_not_found,      // update_item() on an ID that isn't in the vault
        storage,             // any other SQLite or filesystem failure
    };

    VaultError(Kind kind, const std::string& message) : std::runtime_error(message), kind_(kind) {}

    [[nodiscard]] Kind kind() const noexcept { return kind_; }

  private:
    Kind kind_;
};

// Plaintext metadata for one item. Everything else about an item is inside its encrypted body.
struct ItemRecord {
    ItemId id;
    std::int64_t revision = 0; // starts at 1, +1 on every update
    std::chrono::sys_seconds created_at;
    std::chrono::sys_seconds updated_at;
};

// The KDF settings a vault may use. create() and change_master_password() reject anything outside this range, and
// open() refuses a file whose header asks for more, so a tampered file can't make unlock allocate huge memory.
inline constexpr crypto::KdfParams min_vault_kdf{.ops_limit = 1, .mem_limit = std::size_t{8} << 20U};
inline constexpr crypto::KdfParams max_vault_kdf{.ops_limit = 64, .mem_limit = std::size_t{2} << 30U};

[[nodiscard]] bool kdf_params_allowed(const crypto::KdfParams& params) noexcept;

// An unlocked local vault: one SQLite file holding a header (KDF parameters, salt, the Local Vault Key wrapped by
// the KEK) and one encrypted row per item. Item bodies are opaque bytes here; the item model serializes them.
//
// The Local Vault Key lives in a SecureBuffer for as long as the Vault does. Destroying the Vault locks it.
// Every write is a single SQLite transaction in WAL mode with synchronous=FULL.
class Vault {
  public:
    // Creates a new vault file. Fails with VaultError::already_exists if `path` exists and isn't empty.
    // Throws std::invalid_argument for an empty password or KDF params outside [min_vault_kdf, max_vault_kdf].
    [[nodiscard]] static Vault create(const std::filesystem::path& path, const SecureBuffer& master_password,
                                      const crypto::KdfParams& params = {});

    // Opens and unlocks an existing vault. Returns std::nullopt if the password is wrong. Throws VaultError if the
    // file is missing, isn't a vault, is an unsupported version or is corrupt.
    [[nodiscard]] static std::optional<Vault> open(const std::filesystem::path& path,
                                                   const SecureBuffer& master_password);

    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;
    Vault(Vault&& other) noexcept;
    Vault& operator=(Vault&& other) noexcept;
    ~Vault();

    // Encrypts and stores a new item and returns its new random ID.
    [[nodiscard]] ItemId add_item(std::span<const std::byte> body);

    // Returns the decrypted body, or std::nullopt if no such item exists. Throws VaultError::corrupt if the stored
    // ciphertext fails authentication (tampered, truncated or moved from another item or vault).
    [[nodiscard]] std::optional<SecureBuffer> read_item(const ItemId& id) const;

    // Re-encrypts the item with a fresh nonce and bumps its revision. Throws VaultError::item_not_found.
    void update_item(const ItemId& id, std::span<const std::byte> body);

    // Returns false if no such item exists. Deleted content is overwritten on disk (secure_delete).
    bool remove_item(const ItemId& id);

    // All items, oldest first.
    [[nodiscard]] std::vector<ItemRecord> list_items() const;

    // Re-wraps the Local Vault Key under a key derived from the new password, with a new salt. No item is
    // re-encrypted. Same argument checks as create().
    void change_master_password(const SecureBuffer& new_password, const crypto::KdfParams& params = {});

    [[nodiscard]] crypto::KdfParams kdf_params() const;

  private:
    struct Impl;
    explicit Vault(std::unique_ptr<Impl> impl) noexcept;
    [[nodiscard]] Impl& impl() const;

    std::unique_ptr<Impl> impl_;
};

} // namespace ck
