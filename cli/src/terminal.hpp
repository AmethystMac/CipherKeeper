#pragma once

#include "cli.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The real console behind the ck executable. Platform-specific and only used by main(), so it isn't unit tested.
namespace ck::cli {

// Prompts go to stderr, so `ck get --field password x | ...` pipes only the value. Answers are read straight into
// secure memory: on a Windows console as UTF-16 with ReadConsoleW, otherwise byte by byte with stdin unbuffered.
// read_secret turns off echo while it reads.
class TerminalConsole final : public Console {
  public:
    TerminalConsole();

    void out(std::string_view text) override;
    void err(std::string_view text) override;
    [[nodiscard]] std::optional<SecureString> read_line(std::string_view prompt) override;
    [[nodiscard]] std::optional<SecureString> read_secret(std::string_view prompt) override;
};

// The command-line arguments after the program name, as UTF-8 (on Windows, decoded from the wide command line).
[[nodiscard]] std::vector<std::string> utf8_arguments(int argc, char** argv);

// $CK_VAULT if set, otherwise vault.ckvault in the per-user, non-roaming data directory:
// %LOCALAPPDATA%\CipherKeeper on Windows, ~/Library/Application Support/CipherKeeper on macOS,
// $XDG_DATA_HOME/cipherkeeper (default ~/.local/share/cipherkeeper) elsewhere.
[[nodiscard]] std::filesystem::path default_vault_path();

} // namespace ck::cli
