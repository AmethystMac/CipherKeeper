#pragma once

// Minimal RAII wrapper over the SQLite C API, private to core. Failures throw ck::VaultError. Only ciphertext,
// salts and IDs are ever bound: plaintext never reaches SQLite, so its page cache and journals hold nothing secret.

#include "cipherkeeper/storage/vault.hpp"

#include <sqlite3.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace ck::sqlite {

// Throws the VaultError matching the SQLite result `code`, with the connection's error message.
[[noreturn]] void fail(sqlite3* db, int code);

class Statement {
  public:
    // Parameter indexes are 1-based, as in SQLite. Bound blobs must stay alive until the next step().
    void bind(int index, std::span<const std::byte> blob);
    void bind(int index, std::int64_t value);

    // Returns true if a row is available, false when the statement is done.
    [[nodiscard]] bool step();
    // step() for statements that return no rows.
    void run();

    [[nodiscard]] std::int64_t column_int(int index) const noexcept;
    [[nodiscard]] std::vector<std::byte> column_blob(int index) const;
    // SQLITE_INTEGER, SQLITE_BLOB, SQLITE_NULL, ...
    [[nodiscard]] int column_type(int index) const noexcept;

  private:
    friend class Database;
    struct Finalize {
        void operator()(sqlite3_stmt* stmt) const noexcept { sqlite3_finalize(stmt); }
    };
    explicit Statement(sqlite3_stmt* stmt) noexcept : stmt_(stmt) {}

    std::unique_ptr<sqlite3_stmt, Finalize> stmt_;
};

class Database {
  public:
    // `flags` are sqlite3_open_v2 flags (SQLITE_OPEN_READWRITE, optionally SQLITE_OPEN_CREATE).
    [[nodiscard]] static Database open(const std::filesystem::path& path, int flags);

    void exec(const char* sql);
    [[nodiscard]] Statement prepare(const char* sql);
    // Runs a query that returns a single integer (e.g. "PRAGMA user_version").
    [[nodiscard]] std::int64_t query_int(const char* sql);
    [[nodiscard]] std::int64_t changes() const noexcept;

  private:
    struct Close {
        void operator()(sqlite3* db) const noexcept { sqlite3_close_v2(db); }
    };
    explicit Database(std::unique_ptr<sqlite3, Close> db) noexcept : db_(std::move(db)) {}

    std::unique_ptr<sqlite3, Close> db_;
};

// BEGIN IMMEDIATE on construction; rolls back on destruction unless commit() was called.
class Transaction {
  public:
    explicit Transaction(Database& db);
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    Transaction(Transaction&&) = delete;
    Transaction& operator=(Transaction&&) = delete;
    ~Transaction();

    void commit();

  private:
    Database& db_;
    bool committed_ = false;
};

} // namespace ck::sqlite
