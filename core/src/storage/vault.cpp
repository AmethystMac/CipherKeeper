#include "cipherkeeper/storage/vault.hpp"

#include "storage/sqlite.hpp"

#include <algorithm>
#include <array>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

// Vault file format v1
// --------------------
// One SQLite database. The file header's application_id is 0x434B5654 ("CKVT") and its user_version is the format
// version (1). Tables are STRICT:
//
//   vault_header  exactly one row (id = 1):
//     vault_id          16 random bytes, fixed at creation, bound into every ciphertext's associated data
//     kdf_algorithm     1 = Argon2id v1.3
//     kdf_ops_limit, kdf_mem_limit
//     kdf_salt          16 bytes
//     wrapped_local_key seal(KEK, Local Vault Key, "cipherkeeper/v1/local-vault-key" || vault_id)
//     created_at        Unix seconds
//
//   items  one row per item:
//     id                16-byte UUIDv4
//     key_id            which key encrypted body: 1 = Local Vault Key (2 is reserved for the Account Key)
//     revision          1 on insert, +1 on every update
//     created_at, updated_at   Unix seconds
//     body              seal(key, item body, "cipherkeeper/v1/item" || vault_id || id || key_id)
//
// The associated data has a fixed label and then fixed-size fields, so it is unambiguous without length prefixes.
// Binding vault_id and id means a body copied to another row or another vault fails authentication. Only IDs,
// revisions, timestamps and ciphertext sizes are visible without the master password.

namespace ck {

namespace {

constexpr std::int64_t application_id = 0x434B5654; // "CKVT"
constexpr std::int64_t format_version = 1;
constexpr std::int64_t kdf_argon2id13 = 1;
constexpr std::int64_t local_vault_key_id = 1;
constexpr std::size_t vault_id_size = 16;

using VaultId = std::array<std::byte, vault_id_size>;

constexpr std::string_view local_key_ad_label = "cipherkeeper/v1/local-vault-key";
constexpr std::string_view item_ad_label = "cipherkeeper/v1/item";

constexpr const char* schema_sql = R"sql(
CREATE TABLE vault_header (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id          BLOB    NOT NULL CHECK (length(vault_id) = 16),
    kdf_algorithm     INTEGER NOT NULL,
    kdf_ops_limit     INTEGER NOT NULL,
    kdf_mem_limit     INTEGER NOT NULL,
    kdf_salt          BLOB    NOT NULL CHECK (length(kdf_salt) = 16),
    wrapped_local_key BLOB    NOT NULL,
    created_at        INTEGER NOT NULL
) STRICT;

CREATE TABLE items (
    id         BLOB    PRIMARY KEY CHECK (length(id) = 16),
    key_id     INTEGER NOT NULL,
    revision   INTEGER NOT NULL CHECK (revision >= 1),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    body       BLOB    NOT NULL
) STRICT;
)sql";

[[noreturn]] void corrupt(const std::string& what) {
    throw VaultError(VaultError::Kind::corrupt, "vault file is corrupt: " + what);
}

void append(std::vector<std::byte>& out, std::span<const std::byte> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

std::vector<std::byte> local_key_ad(const VaultId& vault_id) {
    std::vector<std::byte> ad;
    append(ad, std::as_bytes(std::span(local_key_ad_label)));
    append(ad, vault_id);
    return ad;
}

std::vector<std::byte> item_ad(const VaultId& vault_id, const ItemId& id, std::int64_t key_id) {
    std::vector<std::byte> ad;
    append(ad, std::as_bytes(std::span(item_ad_label)));
    append(ad, vault_id);
    append(ad, id.bytes());
    ad.push_back(static_cast<std::byte>(key_id));
    return ad;
}

std::int64_t now_unix() {
    const auto now = std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
    return static_cast<std::int64_t>(now.time_since_epoch().count());
}

std::chrono::sys_seconds from_unix(std::int64_t seconds) {
    return std::chrono::sys_seconds(std::chrono::seconds(seconds));
}

void require_create_args(const SecureBuffer& password, const crypto::KdfParams& params) {
    if (password.empty()) {
        throw std::invalid_argument("master password must not be empty");
    }
    if (!kdf_params_allowed(params)) {
        throw std::invalid_argument("KDF parameters are outside the allowed range");
    }
}

// Per-connection settings. journal_mode=WAL is stored in the file itself, so only create() sets it.
void configure(sqlite::Database& db) {
    db.exec("PRAGMA synchronous = FULL; PRAGMA secure_delete = ON;");
}

std::int64_t read_int(const sqlite::Statement& stmt, int column, const char* what) {
    if (stmt.column_type(column) != SQLITE_INTEGER) {
        corrupt(what);
    }
    return stmt.column_int(column);
}

std::vector<std::byte> read_blob(const sqlite::Statement& stmt, int column, const char* what) {
    if (stmt.column_type(column) != SQLITE_BLOB) {
        corrupt(what);
    }
    return stmt.column_blob(column);
}

template <std::size_t N>
std::array<std::byte, N> read_fixed_blob(const sqlite::Statement& stmt, int column, const char* what) {
    const std::vector<std::byte> bytes = read_blob(stmt, column, what);
    if (bytes.size() != N) {
        corrupt(what);
    }
    std::array<std::byte, N> out{};
    std::ranges::copy(bytes, out.begin());
    return out;
}

// A salt and a wrapped Local Vault Key for `password`.
struct WrappedKey {
    crypto::Salt salt{};
    std::vector<std::byte> sealed_key;
};

WrappedKey wrap_local_key(const SecureBuffer& local_key, const SecureBuffer& password, const crypto::KdfParams& params,
                          const VaultId& vault_id) {
    WrappedKey result{.salt = crypto::random_salt(), .sealed_key = {}};
    const crypto::DerivedKeys keys = crypto::derive_subkeys(crypto::derive_master_key(password, result.salt, params));
    result.sealed_key = crypto::seal(keys.kek, local_key.bytes(), local_key_ad(vault_id));
    return result;
}

// Best effort: runs while another exception is in flight, so it must not throw.
void remove_vault_files(const std::filesystem::path& path) noexcept {
    try {
        std::error_code ignored;
        for (const char* suffix : {"", "-wal", "-shm", "-journal"}) {
            std::filesystem::path file = path;
            file += suffix;
            std::filesystem::remove(file, ignored);
        }
    } catch (...) { // NOLINT(bugprone-empty-catch): leftover files are harmless; the original error matters more
    }
}

} // namespace

bool kdf_params_allowed(const crypto::KdfParams& params) noexcept {
    return params.ops_limit >= min_vault_kdf.ops_limit && params.ops_limit <= max_vault_kdf.ops_limit &&
           params.mem_limit >= min_vault_kdf.mem_limit && params.mem_limit <= max_vault_kdf.mem_limit;
}

struct Vault::Impl {
    sqlite::Database db;
    VaultId vault_id{};
    crypto::KdfParams kdf;
    SecureBuffer local_key;
};

Vault::Vault(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
Vault::Vault(Vault&& other) noexcept = default;
Vault& Vault::operator=(Vault&& other) noexcept = default;
Vault::~Vault() = default;

Vault::Impl& Vault::impl() const {
    if (!impl_) {
        throw std::logic_error("use of a moved-from Vault");
    }
    return *impl_;
}

Vault Vault::create(const std::filesystem::path& path, const SecureBuffer& master_password,
                    const crypto::KdfParams& params) {
    require_create_args(master_password, params);

    std::error_code ec;
    const bool existed = std::filesystem::exists(path, ec);
    if (existed && (!std::filesystem::is_regular_file(path, ec) || std::filesystem::file_size(path, ec) != 0)) {
        throw VaultError(VaultError::Kind::already_exists, "a file already exists at the vault path");
    }

    // Only files this call created are removed on failure.
    bool remove_on_failure = !existed;
    try {
        sqlite::Database db = sqlite::Database::open(path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
        db.exec("PRAGMA journal_mode = WAL;");
        configure(db);

        VaultId vault_id{};
        crypto::random_bytes(vault_id);
        SecureBuffer local_key = crypto::random_key();
        const WrappedKey wrapped = wrap_local_key(local_key, master_password, params, vault_id);

        {
            sqlite::Transaction tx(db);
            // Checked again inside the write lock, in case another process created the file in the meantime.
            if (db.query_int("SELECT count(*) FROM sqlite_schema") != 0) {
                remove_on_failure = false;
                throw VaultError(VaultError::Kind::already_exists, "a file already exists at the vault path");
            }
            db.exec(schema_sql);
            db.exec(("PRAGMA application_id = " + std::to_string(application_id) + ";").c_str());
            db.exec(("PRAGMA user_version = " + std::to_string(format_version) + ";").c_str());

            sqlite::Statement insert = db.prepare(
                "INSERT INTO vault_header (id, vault_id, kdf_algorithm, kdf_ops_limit, kdf_mem_limit, kdf_salt, "
                "wrapped_local_key, created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)");
            insert.bind(1, vault_id);
            insert.bind(2, kdf_argon2id13);
            insert.bind(3, static_cast<std::int64_t>(params.ops_limit));
            insert.bind(4, static_cast<std::int64_t>(params.mem_limit));
            insert.bind(5, wrapped.salt);
            insert.bind(6, wrapped.sealed_key);
            insert.bind(7, now_unix());
            insert.run();
            tx.commit();
        }

        return Vault(std::make_unique<Impl>(
            Impl{.db = std::move(db), .vault_id = vault_id, .kdf = params, .local_key = std::move(local_key)}));
    } catch (...) {
        // The database handle is already closed here, so the files can be removed (Windows keeps open files locked).
        if (remove_on_failure) {
            remove_vault_files(path);
        }
        throw;
    }
}

std::optional<Vault> Vault::open(const std::filesystem::path& path, const SecureBuffer& master_password) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) {
        throw VaultError(VaultError::Kind::storage, "no vault file at that path");
    }

    sqlite::Database db = sqlite::Database::open(path, SQLITE_OPEN_READWRITE);
    configure(db);

    // The first read of the file: a non-SQLite file fails here with not_a_vault.
    if (db.query_int("PRAGMA application_id") != application_id) {
        throw VaultError(VaultError::Kind::not_a_vault, "not a CipherKeeper vault");
    }
    const std::int64_t version = db.query_int("PRAGMA user_version");
    if (version > format_version) {
        throw VaultError(VaultError::Kind::unsupported_version, "vault was created by a newer CipherKeeper version");
    }
    if (version < 1) {
        corrupt("missing format version");
    }
    // The vault never defines triggers or views, so their presence means someone else wrote this schema.
    if (db.query_int("SELECT count(*) FROM sqlite_schema WHERE type IN ('trigger', 'view')") != 0) {
        corrupt("unexpected schema objects");
    }

    sqlite::Statement header = db.prepare("SELECT vault_id, kdf_algorithm, kdf_ops_limit, kdf_mem_limit, kdf_salt, "
                                          "wrapped_local_key FROM vault_header WHERE id = 1");
    if (!header.step()) {
        corrupt("missing header");
    }
    const auto vault_id = read_fixed_blob<vault_id_size>(header, 0, "bad vault ID");
    if (read_int(header, 1, "bad KDF algorithm") != kdf_argon2id13) {
        throw VaultError(VaultError::Kind::unsupported_version, "vault uses an unknown KDF");
    }
    const std::int64_t ops = read_int(header, 2, "bad KDF ops limit");
    const std::int64_t mem = read_int(header, 3, "bad KDF memory limit");
    // Range-check before converting, and before Argon2id would try to allocate whatever the header asks for.
    if (ops < 1 || mem < 1 || static_cast<std::uint64_t>(ops) > max_vault_kdf.ops_limit ||
        static_cast<std::uint64_t>(mem) > max_vault_kdf.mem_limit) {
        corrupt("KDF parameters out of range");
    }
    const crypto::KdfParams params{.ops_limit = static_cast<std::uint64_t>(ops),
                                   .mem_limit = static_cast<std::size_t>(mem)};
    if (!kdf_params_allowed(params)) {
        corrupt("KDF parameters out of range");
    }
    const auto salt = read_fixed_blob<crypto::salt_size>(header, 4, "bad KDF salt");
    const std::vector<std::byte> wrapped = read_blob(header, 5, "bad wrapped key");

    const crypto::DerivedKeys keys = crypto::derive_subkeys(crypto::derive_master_key(master_password, salt, params));
    std::optional<SecureBuffer> local_key = crypto::open(keys.kek, wrapped, local_key_ad(vault_id));
    if (!local_key) {
        // A wrong password and a tampered header look the same, by design.
        return std::nullopt;
    }
    if (local_key->size() != crypto::key_size) {
        corrupt("bad local vault key");
    }

    return Vault(std::make_unique<Impl>(
        Impl{.db = std::move(db), .vault_id = vault_id, .kdf = params, .local_key = std::move(*local_key)}));
}

ItemId Vault::add_item(std::span<const std::byte> body) {
    Impl& self = impl();
    const ItemId id = ItemId::generate();
    const std::vector<std::byte> sealed =
        crypto::seal(self.local_key, body, item_ad(self.vault_id, id, local_vault_key_id));
    const std::int64_t now = now_unix();

    sqlite::Statement insert = self.db.prepare("INSERT INTO items (id, key_id, revision, created_at, updated_at, body) "
                                               "VALUES (?1, ?2, 1, ?3, ?3, ?4)");
    insert.bind(1, id.bytes());
    insert.bind(2, local_vault_key_id);
    insert.bind(3, now);
    insert.bind(4, sealed);
    insert.run();
    return id;
}

std::optional<SecureBuffer> Vault::read_item(const ItemId& id) const {
    Impl& self = impl();
    sqlite::Statement select = self.db.prepare("SELECT key_id, body FROM items WHERE id = ?1");
    select.bind(1, id.bytes());
    if (!select.step()) {
        return std::nullopt;
    }
    const std::int64_t key_id = read_int(select, 0, "bad item key ID");
    if (key_id != local_vault_key_id) {
        corrupt("item uses an unknown key");
    }
    const std::vector<std::byte> sealed = read_blob(select, 1, "bad item body");

    std::optional<SecureBuffer> body = crypto::open(self.local_key, sealed, item_ad(self.vault_id, id, key_id));
    if (!body) {
        corrupt("item failed authentication");
    }
    return body;
}

void Vault::update_item(const ItemId& id, std::span<const std::byte> body) {
    Impl& self = impl();
    const std::vector<std::byte> sealed =
        crypto::seal(self.local_key, body, item_ad(self.vault_id, id, local_vault_key_id));

    sqlite::Statement update = self.db.prepare("UPDATE items SET key_id = ?1, body = ?2, revision = revision + 1, "
                                               "updated_at = ?3 WHERE id = ?4");
    update.bind(1, local_vault_key_id);
    update.bind(2, sealed);
    update.bind(3, now_unix());
    update.bind(4, id.bytes());
    update.run();
    if (self.db.changes() == 0) {
        throw VaultError(VaultError::Kind::item_not_found, "no item with that ID");
    }
}

bool Vault::remove_item(const ItemId& id) {
    Impl& self = impl();
    sqlite::Statement remove = self.db.prepare("DELETE FROM items WHERE id = ?1");
    remove.bind(1, id.bytes());
    remove.run();
    return self.db.changes() > 0;
}

std::vector<ItemRecord> Vault::list_items() const {
    Impl& self = impl();
    sqlite::Statement select =
        self.db.prepare("SELECT id, revision, created_at, updated_at FROM items ORDER BY created_at, id");
    std::vector<ItemRecord> records;
    while (select.step()) {
        const auto id = read_fixed_blob<ItemId::size>(select, 0, "bad item ID");
        records.push_back({.id = ItemId::from_bytes(id),
                           .revision = read_int(select, 1, "bad item revision"),
                           .created_at = from_unix(read_int(select, 2, "bad item timestamp")),
                           .updated_at = from_unix(read_int(select, 3, "bad item timestamp"))});
    }
    return records;
}

void Vault::change_master_password(const SecureBuffer& new_password, const crypto::KdfParams& params) {
    Impl& self = impl();
    require_create_args(new_password, params);
    const WrappedKey wrapped = wrap_local_key(self.local_key, new_password, params, self.vault_id);

    // One UPDATE, so a crash leaves either the old password or the new one working, never neither.
    sqlite::Statement update =
        self.db.prepare("UPDATE vault_header SET kdf_algorithm = ?1, kdf_ops_limit = ?2, kdf_mem_limit = ?3, "
                        "kdf_salt = ?4, wrapped_local_key = ?5 WHERE id = 1");
    update.bind(1, kdf_argon2id13);
    update.bind(2, static_cast<std::int64_t>(params.ops_limit));
    update.bind(3, static_cast<std::int64_t>(params.mem_limit));
    update.bind(4, wrapped.salt);
    update.bind(5, wrapped.sealed_key);
    update.run();
    if (self.db.changes() != 1) {
        corrupt("missing header");
    }
    self.kdf = params;
}

crypto::KdfParams Vault::kdf_params() const {
    return impl().kdf;
}

} // namespace ck
