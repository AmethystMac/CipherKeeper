#include "storage/sqlite.hpp"

#include <climits>
#include <string>

namespace ck::sqlite {

void fail(sqlite3* db, int code) {
    const std::string message = db != nullptr ? sqlite3_errmsg(db) : sqlite3_errstr(code);
    switch (code & 0xff) {
    case SQLITE_NOTADB:
        throw VaultError(VaultError::Kind::not_a_vault, "not a vault file (" + message + ")");
    case SQLITE_CORRUPT:
        throw VaultError(VaultError::Kind::corrupt, "vault file is corrupt (" + message + ")");
    default:
        throw VaultError(VaultError::Kind::storage, "vault storage error (" + message + ")");
    }
}

// ---- Statement ----------------------------------------------------------------------------------------------------

void Statement::bind(int index, std::span<const std::byte> blob) {
    if (blob.size() > static_cast<std::size_t>(INT_MAX)) {
        throw VaultError(VaultError::Kind::storage, "value is too large to store");
    }
    // A null data pointer would bind SQL NULL, so an empty blob needs bind_zeroblob. For the rest, a null destructor
    // is SQLITE_STATIC: SQLite doesn't copy the data, which the caller keeps alive until step().
    const int rc = blob.empty()
                       ? sqlite3_bind_zeroblob(stmt_.get(), index, 0)
                       : sqlite3_bind_blob(stmt_.get(), index, blob.data(), static_cast<int>(blob.size()), nullptr);
    if (rc != SQLITE_OK) {
        fail(sqlite3_db_handle(stmt_.get()), rc);
    }
}

void Statement::bind(int index, std::int64_t value) {
    const int rc = sqlite3_bind_int64(stmt_.get(), index, value);
    if (rc != SQLITE_OK) {
        fail(sqlite3_db_handle(stmt_.get()), rc);
    }
}

bool Statement::step() {
    const int rc = sqlite3_step(stmt_.get());
    if (rc == SQLITE_ROW) {
        return true;
    }
    if (rc == SQLITE_DONE) {
        return false;
    }
    fail(sqlite3_db_handle(stmt_.get()), rc);
}

void Statement::run() {
    if (step()) {
        throw VaultError(VaultError::Kind::storage, "statement returned rows unexpectedly");
    }
}

std::int64_t Statement::column_int(int index) const noexcept {
    return sqlite3_column_int64(stmt_.get(), index);
}

std::vector<std::byte> Statement::column_blob(int index) const {
    // sqlite3_column_bytes must come after sqlite3_column_blob (see the SQLite docs on type conversions).
    const auto* data = static_cast<const std::byte*>(sqlite3_column_blob(stmt_.get(), index));
    const int size = sqlite3_column_bytes(stmt_.get(), index);
    if (data == nullptr || size <= 0) {
        return {};
    }
    const std::span<const std::byte> bytes(data, static_cast<std::size_t>(size));
    return {bytes.begin(), bytes.end()};
}

int Statement::column_type(int index) const noexcept {
    return sqlite3_column_type(stmt_.get(), index);
}

// ---- Database -----------------------------------------------------------------------------------------------------

Database Database::open(const std::filesystem::path& path, int flags) {
    // SQLite expects UTF-8 file names on every platform, including Windows.
    const std::u8string utf8 = path.u8string();
    const std::string name(reinterpret_cast<const char*>(utf8.data()), utf8.size());

    sqlite3* raw = nullptr;
    const int rc = sqlite3_open_v2(name.c_str(), &raw, flags | SQLITE_OPEN_EXRESCODE, nullptr);
    std::unique_ptr<sqlite3, Close> db(raw); // sqlite3_open_v2 allocates a handle even when it fails
    if (rc != SQLITE_OK) {
        fail(raw, rc);
    }

    // A vault file may come from somewhere untrusted (e.g. a restored backup). Defensive mode blocks writes that
    // could corrupt the file structure, and an untrusted schema can't call side-effecting SQL functions.
    // NOLINTBEGIN(cppcoreguidelines-pro-type-vararg): sqlite3_db_config is the only API for these settings.
    sqlite3_db_config(raw, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
    sqlite3_db_config(raw, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr);
    // NOLINTEND(cppcoreguidelines-pro-type-vararg)
    sqlite3_busy_timeout(raw, 5000);
    return Database(std::move(db));
}

void Database::exec(const char* sql) {
    const int rc = sqlite3_exec(db_.get(), sql, nullptr, nullptr, nullptr);
    if (rc != SQLITE_OK) {
        fail(db_.get(), rc);
    }
}

Statement Database::prepare(const char* sql) {
    sqlite3_stmt* stmt = nullptr;
    const int rc = sqlite3_prepare_v3(db_.get(), sql, -1, 0, &stmt, nullptr);
    Statement statement(stmt);
    if (rc != SQLITE_OK) {
        fail(db_.get(), rc);
    }
    return statement;
}

std::int64_t Database::query_int(const char* sql) {
    Statement stmt = prepare(sql);
    if (!stmt.step()) {
        throw VaultError(VaultError::Kind::storage, "query returned no rows");
    }
    return stmt.column_int(0);
}

std::int64_t Database::changes() const noexcept {
    return sqlite3_changes64(db_.get());
}

// ---- Transaction --------------------------------------------------------------------------------------------------

Transaction::Transaction(Database& db) : db_(db) {
    db_.exec("BEGIN IMMEDIATE");
}

Transaction::~Transaction() {
    if (!committed_) {
        try {
            db_.exec("ROLLBACK");
        } catch (...) { // NOLINT(bugprone-empty-catch): a failed rollback still ends the transaction
        }
    }
}

void Transaction::commit() {
    db_.exec("COMMIT");
    committed_ = true;
}

} // namespace ck::sqlite
