#pragma once

#include "cli.hpp"

#include <cipherkeeper/storage/vault.hpp>

#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace ck::cli {

// Ends a command with an exit code. The message is printed after "ck: " and must not contain secrets.
class Failure : public std::runtime_error {
  public:
    Failure(Exit code, const std::string& message) : std::runtime_error(message), code_(code) {}

    [[nodiscard]] Exit code() const noexcept { return code_; }

  private:
    Exit code_;
};

// State for one ck invocation, or for a whole unlock session.
class Context {
  public:
    Context(Console& console, const Settings& settings, std::filesystem::path vault_path)
        : console_(&console), settings_(&settings), vault_path_(std::move(vault_path)) {}

    [[nodiscard]] Console& console() const noexcept { return *console_; }
    [[nodiscard]] const Settings& settings() const noexcept { return *settings_; }
    [[nodiscard]] const std::filesystem::path& vault_path() const noexcept { return vault_path_; }

    // The unlocked vault. The first call asks for the master password (up to three times).
    [[nodiscard]] Vault& vault();
    // Asks for the master password again and replaces the open vault with the newly unlocked one.
    void unlock_again();

    void start_session() noexcept { in_session_ = true; }
    [[nodiscard]] bool in_session() const noexcept { return in_session_; }

  private:
    [[nodiscard]] Vault unlock() const;

    Console* console_;
    const Settings* settings_;
    std::filesystem::path vault_path_;
    std::optional<Vault> vault_;
    bool in_session_ = false;
};

using Args = std::span<const std::string>;

// Each command gets the words after its name. Usage errors are thrown before the vault is unlocked.
Exit init_command(Context& ctx, Args args);
Exit add_command(Context& ctx, Args args);
Exit list_command(Context& ctx, Args args);
Exit get_command(Context& ctx, Args args);
Exit edit_command(Context& ctx, Args args);
Exit rm_command(Context& ctx, Args args);
Exit change_master_command(Context& ctx, Args args);

[[nodiscard]] std::filesystem::path path_from_utf8(std::string_view text);
[[nodiscard]] std::string path_to_utf8(const std::filesystem::path& path);

} // namespace ck::cli
