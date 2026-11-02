#include "storage/sqlite.hpp"
#include "test_util.hpp"

#include <cipherkeeper/storage/vault.hpp>

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_predicate.hpp>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using ck::ItemId;
using ck::SecureBuffer;
using ck::Vault;
using ck::VaultError;
using ck::test::bytes_of;
using ck::test::same_bytes;
using ck::test::secret;
using ck::test::TempDir;

namespace {

// The cheapest KDF settings a vault accepts, so tests stay fast. Throwaway passwords only.
constexpr ck::crypto::KdfParams test_kdf = ck::min_vault_kdf;
constexpr std::string_view password = "throwaway-test-password";

Vault create_vault(const std::filesystem::path& path) {
    return Vault::create(path, secret(password), test_kdf);
}

Vault open_vault(const std::filesystem::path& path) {
    std::optional<Vault> vault = Vault::open(path, secret(password));
    REQUIRE(vault.has_value());
    return std::move(*vault);
}

// Raw access to the file, bypassing Vault, to simulate an attacker or a damaged disk.
ck::sqlite::Database raw(const std::filesystem::path& path) {
    return ck::sqlite::Database::open(path, SQLITE_OPEN_READWRITE);
}

std::vector<std::byte> read_body(const std::filesystem::path& path, const ItemId& id) {
    ck::sqlite::Database db = raw(path);
    ck::sqlite::Statement select = db.prepare("SELECT body FROM items WHERE id = ?1");
    select.bind(1, id.bytes());
    REQUIRE(select.step());
    return select.column_blob(0);
}

void write_body(const std::filesystem::path& path, const ItemId& id, std::span<const std::byte> body) {
    ck::sqlite::Database db = raw(path);
    ck::sqlite::Statement update = db.prepare("UPDATE items SET body = ?1 WHERE id = ?2");
    update.bind(1, body);
    update.bind(2, id.bytes());
    update.run();
}

void write_header_blob(const std::filesystem::path& path, const char* column, std::span<const std::byte> value) {
    ck::sqlite::Database db = raw(path);
    const std::string sql = std::string("UPDATE vault_header SET ") + column + " = ?1";
    ck::sqlite::Statement update = db.prepare(sql.c_str());
    update.bind(1, value);
    update.run();
}

std::vector<std::byte> read_header_blob(const std::filesystem::path& path, const char* column) {
    ck::sqlite::Database db = raw(path);
    const std::string sql = std::string("SELECT ") + column + " FROM vault_header";
    ck::sqlite::Statement select = db.prepare(sql.c_str());
    REQUIRE(select.step());
    return select.column_blob(0);
}

auto is_kind(VaultError::Kind kind) {
    return Catch::Matchers::Predicate<VaultError>([kind](const VaultError& e) { return e.kind() == kind; },
                                                  "VaultError of the expected kind");
}

} // namespace

// ---- Round trips --------------------------------------------------------------------------------------------------

TEST_CASE("a new vault stores items and reopens with the same password") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";

    ItemId id;
    {
        Vault vault = create_vault(path);
        id = vault.add_item(bytes_of("first item body"));
        const std::optional<SecureBuffer> body = vault.read_item(id);
        REQUIRE(body.has_value());
        CHECK(same_bytes(body->bytes(), bytes_of("first item body")));
    }

    const Vault reopened = open_vault(path);
    const std::optional<SecureBuffer> body = reopened.read_item(id);
    REQUIRE(body.has_value());
    CHECK(same_bytes(body->bytes(), bytes_of("first item body")));
    CHECK(reopened.kdf_params() == test_kdf);
}

TEST_CASE("an empty item body round-trips") {
    const TempDir dir;
    Vault vault = create_vault(dir.path() / "test.ckvault");
    const ItemId id = vault.add_item({});
    const std::optional<SecureBuffer> body = vault.read_item(id);
    REQUIRE(body.has_value());
    CHECK(body->empty());
}

TEST_CASE("updating an item replaces its body and bumps its revision") {
    const TempDir dir;
    Vault vault = create_vault(dir.path() / "test.ckvault");
    const ItemId id = vault.add_item(bytes_of("v1"));
    vault.update_item(id, bytes_of("version two"));

    const std::optional<SecureBuffer> body = vault.read_item(id);
    REQUIRE(body.has_value());
    CHECK(same_bytes(body->bytes(), bytes_of("version two")));

    const std::vector<ck::ItemRecord> records = vault.list_items();
    REQUIRE(records.size() == 1);
    CHECK(records[0].id == id);
    CHECK(records[0].revision == 2);
    CHECK(records[0].updated_at >= records[0].created_at);
}

TEST_CASE("updating a missing item throws item_not_found") {
    const TempDir dir;
    Vault vault = create_vault(dir.path() / "test.ckvault");
    CHECK_THROWS_MATCHES(vault.update_item(ItemId::generate(), bytes_of("x")), VaultError,
                         is_kind(VaultError::Kind::item_not_found));
}

TEST_CASE("removing an item deletes it") {
    const TempDir dir;
    Vault vault = create_vault(dir.path() / "test.ckvault");
    const ItemId keep = vault.add_item(bytes_of("keep"));
    const ItemId drop = vault.add_item(bytes_of("drop"));

    CHECK(vault.remove_item(drop));
    CHECK_FALSE(vault.read_item(drop).has_value());
    CHECK_FALSE(vault.remove_item(drop));
    CHECK(vault.read_item(keep).has_value());
    REQUIRE(vault.list_items().size() == 1);
    CHECK(vault.list_items()[0].id == keep);
}

TEST_CASE("reading an unknown item returns nothing") {
    const TempDir dir;
    const Vault vault = create_vault(dir.path() / "test.ckvault");
    CHECK_FALSE(vault.read_item(ItemId::generate()).has_value());
    CHECK(vault.list_items().empty());
}

TEST_CASE("item contents never appear in the vault file") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";
    constexpr std::string_view marker = "UNMISTAKABLE-PLAINTEXT-MARKER-7f3a";
    {
        Vault vault = create_vault(path);
        const ItemId id = vault.add_item(bytes_of(marker));
        vault.update_item(id, bytes_of(std::string(marker) + "-updated"));
    }
    // Check the main file and any journal files SQLite left beside it.
    for (const auto& entry : std::filesystem::directory_iterator(dir.path())) {
        std::ifstream file(entry.path(), std::ios::binary);
        const std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        INFO(entry.path().filename().string());
        CHECK(contents.find(marker) == std::string::npos);
        CHECK(contents.find(password) == std::string::npos);
    }
}

// ---- Passwords ----------------------------------------------------------------------------------------------------

TEST_CASE("a wrong password doesn't open the vault") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";
    { (void)create_vault(path); }
    CHECK_FALSE(Vault::open(path, secret("throwaway-test-passwore")).has_value());
}

TEST_CASE("changing the master password re-wraps the key and keeps every item") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";
    const ck::crypto::KdfParams new_kdf{.ops_limit = 2, .mem_limit = test_kdf.mem_limit};

    ItemId id;
    {
        Vault vault = create_vault(path);
        id = vault.add_item(bytes_of("survives the change"));
        vault.change_master_password(secret("new-throwaway-password"), new_kdf);
        CHECK(vault.kdf_params() == new_kdf);
    }

    CHECK_FALSE(Vault::open(path, secret(password)).has_value());
    std::optional<Vault> vault = Vault::open(path, secret("new-throwaway-password"));
    REQUIRE(vault.has_value());
    CHECK(vault->kdf_params() == new_kdf);
    const std::optional<SecureBuffer> body = vault->read_item(id);
    REQUIRE(body.has_value());
    CHECK(same_bytes(body->bytes(), bytes_of("survives the change")));
}

TEST_CASE("create and change_master_password reject bad arguments") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";

    CHECK_THROWS_AS(Vault::create(path, SecureBuffer{}, test_kdf), std::invalid_argument);
    CHECK_THROWS_AS(Vault::create(path, secret(password), {.ops_limit = 1, .mem_limit = std::size_t{1} << 20U}),
                    std::invalid_argument);
    CHECK_THROWS_AS(Vault::create(path, secret(password), {.ops_limit = 65, .mem_limit = test_kdf.mem_limit}),
                    std::invalid_argument);
    CHECK_FALSE(std::filesystem::exists(path));

    Vault vault = create_vault(path);
    CHECK_THROWS_AS(vault.change_master_password(SecureBuffer{}, test_kdf), std::invalid_argument);
}

// ---- Creating over existing files ---------------------------------------------------------------------------------

TEST_CASE("create refuses to overwrite an existing vault") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";
    ItemId id;
    {
        Vault vault = create_vault(path);
        id = vault.add_item(bytes_of("precious"));
    }

    CHECK_THROWS_MATCHES(create_vault(path), VaultError, is_kind(VaultError::Kind::already_exists));

    // The failed create must leave the original untouched.
    const Vault vault = open_vault(path);
    CHECK(vault.read_item(id).has_value());
}

TEST_CASE("create refuses a non-empty file that isn't a vault") {
    const TempDir dir;
    const auto path = dir.path() / "notes.txt";
    std::ofstream(path) << "not a vault";
    CHECK_THROWS_MATCHES(create_vault(path), VaultError, is_kind(VaultError::Kind::already_exists));
    CHECK(std::filesystem::file_size(path) == 11);
}

// ---- Files that aren't valid vaults -------------------------------------------------------------------------------

TEST_CASE("open rejects files that aren't vaults") {
    const TempDir dir;

    SECTION("a missing file") {
        CHECK_THROWS_MATCHES(Vault::open(dir.path() / "missing.ckvault", secret(password)), VaultError,
                             is_kind(VaultError::Kind::storage));
        CHECK_FALSE(std::filesystem::exists(dir.path() / "missing.ckvault"));
    }
    SECTION("a text file") {
        const auto path = dir.path() / "notes.txt";
        std::ofstream(path) << "This is a text file, long enough to be read as a SQLite header but not one.";
        CHECK_THROWS_MATCHES(Vault::open(path, secret(password)), VaultError, is_kind(VaultError::Kind::not_a_vault));
    }
    SECTION("another application's SQLite database") {
        const auto path = dir.path() / "other.db";
        {
            ck::sqlite::Database db = ck::sqlite::Database::open(path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
            db.exec("CREATE TABLE t (x INTEGER);");
        }
        CHECK_THROWS_MATCHES(Vault::open(path, secret(password)), VaultError, is_kind(VaultError::Kind::not_a_vault));
    }
}

TEST_CASE("open rejects a vault from a newer format version") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";
    { (void)create_vault(path); }
    raw(path).exec("PRAGMA user_version = 2;");
    CHECK_THROWS_MATCHES(Vault::open(path, secret(password)), VaultError,
                         is_kind(VaultError::Kind::unsupported_version));
}

TEST_CASE("open rejects a vault with triggers added") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";
    { (void)create_vault(path); }
    raw(path).exec("CREATE TRIGGER spy AFTER INSERT ON items BEGIN SELECT 1; END;");
    CHECK_THROWS_MATCHES(Vault::open(path, secret(password)), VaultError, is_kind(VaultError::Kind::corrupt));
}

// ---- Tampered headers ---------------------------------------------------------------------------------------------

TEST_CASE("a tampered header fails to unlock") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";
    { (void)create_vault(path); }

    SECTION("wrapped key bit flip") {
        std::vector<std::byte> wrapped = read_header_blob(path, "wrapped_local_key");
        wrapped.back() ^= std::byte{1};
        write_header_blob(path, "wrapped_local_key", wrapped);
        CHECK_FALSE(Vault::open(path, secret(password)).has_value());
    }
    SECTION("salt changed") {
        std::vector<std::byte> salt = read_header_blob(path, "kdf_salt");
        salt[0] ^= std::byte{1};
        write_header_blob(path, "kdf_salt", salt);
        CHECK_FALSE(Vault::open(path, secret(password)).has_value());
    }
    SECTION("vault ID changed") {
        std::vector<std::byte> vault_id = read_header_blob(path, "vault_id");
        vault_id[0] ^= std::byte{1};
        write_header_blob(path, "vault_id", vault_id);
        CHECK_FALSE(Vault::open(path, secret(password)).has_value());
    }
    SECTION("wrapped key truncated") {
        const std::vector<std::byte> wrapped = read_header_blob(path, "wrapped_local_key");
        write_header_blob(path, "wrapped_local_key", std::span(wrapped).first(10));
        CHECK_FALSE(Vault::open(path, secret(password)).has_value());
    }
    SECTION("KDF passes lowered") {
        raw(path).exec("UPDATE vault_header SET kdf_ops_limit = 2;");
        CHECK_FALSE(Vault::open(path, secret(password)).has_value());
    }
}

TEST_CASE("a malformed header is reported as corrupt") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";
    { (void)create_vault(path); }

    SECTION("huge memory limit is refused before Argon2id runs") {
        raw(path).exec("UPDATE vault_header SET kdf_mem_limit = 1099511627776;"); // 1 TiB
        CHECK_THROWS_MATCHES(Vault::open(path, secret(password)), VaultError, is_kind(VaultError::Kind::corrupt));
    }
    SECTION("negative passes") {
        raw(path).exec("UPDATE vault_header SET kdf_ops_limit = -1;");
        CHECK_THROWS_MATCHES(Vault::open(path, secret(password)), VaultError, is_kind(VaultError::Kind::corrupt));
    }
    SECTION("header row deleted") {
        raw(path).exec("DELETE FROM vault_header;");
        CHECK_THROWS_MATCHES(Vault::open(path, secret(password)), VaultError, is_kind(VaultError::Kind::corrupt));
    }
    SECTION("unknown KDF algorithm") {
        raw(path).exec("UPDATE vault_header SET kdf_algorithm = 7;");
        CHECK_THROWS_MATCHES(Vault::open(path, secret(password)), VaultError,
                             is_kind(VaultError::Kind::unsupported_version));
    }
}

// ---- Tampered items -----------------------------------------------------------------------------------------------

TEST_CASE("a tampered item fails authentication") {
    const TempDir dir;
    const auto path = dir.path() / "test.ckvault";
    ItemId first;
    ItemId second;
    {
        Vault vault = create_vault(path);
        first = vault.add_item(bytes_of("first secret"));
        second = vault.add_item(bytes_of("second secret"));
    }

    SECTION("one flipped bit") {
        std::vector<std::byte> body = read_body(path, first);
        body[body.size() / 2] ^= std::byte{0x80};
        write_body(path, first, body);
    }
    SECTION("truncated body") {
        const std::vector<std::byte> body = read_body(path, first);
        write_body(path, first, std::span(body).first(30));
    }
    SECTION("bodies swapped between items") {
        const std::vector<std::byte> a = read_body(path, first);
        const std::vector<std::byte> b = read_body(path, second);
        write_body(path, first, b);
        write_body(path, second, a);
    }
    SECTION("key ID changed") {
        raw(path).exec("UPDATE items SET key_id = 2;");
    }

    const Vault vault = open_vault(path);
    CHECK_THROWS_MATCHES(vault.read_item(first), VaultError, is_kind(VaultError::Kind::corrupt));
}

TEST_CASE("an item copied from another vault fails authentication") {
    const TempDir dir;
    const auto path_a = dir.path() / "a.ckvault";
    const auto path_b = dir.path() / "b.ckvault";

    ItemId id_a;
    ItemId id_b;
    {
        Vault a = create_vault(path_a);
        Vault b = create_vault(path_b);
        id_a = a.add_item(bytes_of("from vault a"));
        id_b = b.add_item(bytes_of("from vault b"));
    }
    // Same password, but each vault has its own random Local Vault Key and vault ID.
    {
        ck::sqlite::Database db = raw(path_b);
        ck::sqlite::Statement update = db.prepare("UPDATE items SET id = ?1, body = ?2 WHERE id = ?3");
        const std::vector<std::byte> body = read_body(path_a, id_a);
        update.bind(1, id_a.bytes());
        update.bind(2, body);
        update.bind(3, id_b.bytes());
        update.run();
    }
    const Vault b = open_vault(path_b);
    CHECK_THROWS_MATCHES(b.read_item(id_a), VaultError, is_kind(VaultError::Kind::corrupt));
}

TEST_CASE("using a moved-from vault throws") {
    const TempDir dir;
    Vault vault = create_vault(dir.path() / "test.ckvault");
    const Vault moved = std::move(vault);
    // NOLINTNEXTLINE(bugprone-use-after-move,clang-analyzer-cplusplus.Move): the moved-from state is the point
    CHECK_THROWS_AS(vault.list_items(), std::logic_error);
    CHECK(moved.list_items().empty());
}
