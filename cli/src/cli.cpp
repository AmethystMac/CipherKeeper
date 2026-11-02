#include "cli.hpp"

#include "commands.hpp"

#include <cipherkeeper/core.hpp>
#include <cipherkeeper/model/item_codec.hpp>
#include <cipherkeeper/storage/vault.hpp>

#include <array>
#include <exception>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ck::cli {

namespace {

constexpr std::string_view help_text = R"(Usage: ck [--vault PATH] <command> [arguments]

Commands:
  init                                 create a new vault
  unlock                               unlock once and type commands until lock, exit or quit
  add <login|note|card|identity>       add an item (you'll be asked for each field)
  list [--type TYPE] [query]           list items whose title contains the query
  get [--show] [--field NAME] <query>  show an item; secrets are masked unless --show
  edit <query>                         change an item (empty keeps a field, "-" clears it)
  rm [--yes] <query>                   delete an item
  change-master                        change the master password
  help                                 show this help
  version                              show version information

A query is an ID (or its first few characters) or a title, or part of one.
Passwords and other secrets are always typed at a prompt, never given as arguments.
)";

Exit help_command(Context& ctx, Args /*args*/) {
    ctx.console().out(help_text);
    return Exit::ok;
}

Exit version_command(Context& ctx, Args /*args*/) {
    const LibraryVersions libs = library_versions();
    ctx.console().out("ck " + std::string(version()) + " (libsodium " + std::string(libs.sodium) + ", SQLite " +
                      std::string(libs.sqlite) + ")\n");
    return Exit::ok;
}

Exit unlock_command(Context& ctx, Args args);

struct Command {
    std::string_view name;
    Exit (*run)(Context&, Args);
    bool in_session; // allowed at the unlock prompt
};

constexpr std::array commands{
    Command{.name = "init", .run = init_command, .in_session = false},
    Command{.name = "unlock", .run = unlock_command, .in_session = false},
    Command{.name = "add", .run = add_command, .in_session = true},
    Command{.name = "list", .run = list_command, .in_session = true},
    Command{.name = "get", .run = get_command, .in_session = true},
    Command{.name = "edit", .run = edit_command, .in_session = true},
    Command{.name = "rm", .run = rm_command, .in_session = true},
    Command{.name = "change-master", .run = change_master_command, .in_session = true},
    Command{.name = "help", .run = help_command, .in_session = true},
    Command{.name = "version", .run = version_command, .in_session = true},
};

void report(Console& console, std::string_view message) {
    console.err("ck: ");
    console.err(message);
    console.err("\n");
}

// Runs one command line (the command name and its arguments) and reports any error.
Exit run_command(Context& ctx, Args words) {
    Console& console = ctx.console();
    try {
        const std::string& name = words.front();
        for (const Command& command : commands) {
            if (command.name != name) {
                continue;
            }
            if (ctx.in_session() && !command.in_session) {
                throw Failure(Exit::usage, name + " isn't available while unlocked");
            }
            return command.run(ctx, words.subspan(1));
        }
        throw Failure(Exit::usage, "unknown command \"" + name + "\"");
    } catch (const Failure& e) {
        report(console, e.what());
        if (e.code() == Exit::usage && !ctx.in_session()) {
            console.err("Run 'ck help' for usage.\n");
        }
        return e.code();
    } catch (const VaultError& e) {
        report(console, e.what());
    } catch (const ItemFormatError& e) {
        report(console, std::string("an item can't be read: ") + e.what());
    } catch (const std::exception& e) {
        report(console, e.what());
    }
    return Exit::failure;
}

Exit unlock_command(Context& ctx, Args args) {
    if (!args.empty()) {
        throw Failure(Exit::usage, "unlock takes no arguments");
    }
    Console& console = ctx.console();
    (void)ctx.vault();
    ctx.start_session();
    console.err("Unlocked. Type help for commands, or lock when you're done.\n");

    while (true) {
        const std::optional<SecureString> line = console.read_line("ck> ");
        if (!line) {
            break;
        }
        const std::optional<std::vector<std::string>> words = split_words(line->view());
        if (!words) {
            report(console, "unterminated quote");
            continue;
        }
        if (words->empty()) {
            continue;
        }
        const std::string& name = words->front();
        if (name == "lock" || name == "exit" || name == "quit") {
            break;
        }
        if (run_command(ctx, *words) == Exit::wrong_password) {
            report(console, "locked after too many wrong passwords");
            return Exit::wrong_password;
        }
    }
    console.err("Locked.\n");
    return Exit::ok;
}

Failure usage_error(const std::string& message) {
    return {Exit::usage, message};
}

} // namespace

Exit run(std::span<const std::string> args, Console& console, const Settings& settings) noexcept {
    try {
        std::filesystem::path vault_path = settings.default_vault;
        std::size_t i = 0;
        try {
            for (; i < args.size() && args[i].starts_with("-"); ++i) {
                const std::string& option = args[i];
                if (option == "--vault") {
                    if (++i == args.size()) {
                        throw usage_error("--vault needs a path");
                    }
                    vault_path = path_from_utf8(args[i]);
                } else if (option.starts_with("--vault=")) {
                    vault_path = path_from_utf8(std::string_view(option).substr(std::string_view("--vault=").size()));
                } else if (option == "--help" || option == "-h") {
                    console.out(help_text);
                    return Exit::ok;
                } else if (option == "--version") {
                    Context ctx(console, settings, vault_path);
                    return version_command(ctx, {});
                } else {
                    throw usage_error("unknown option " + option);
                }
            }
            if (i == args.size()) {
                console.err(help_text);
                return Exit::usage;
            }
        } catch (const Failure& e) {
            report(console, e.what());
            console.err("Run 'ck help' for usage.\n");
            return e.code();
        }

        Context ctx(console, settings, std::move(vault_path));
        return run_command(ctx, args.subspan(i));
    } catch (...) {
        try {
            report(console, "unexpected error");
        } catch (...) { // NOLINT(bugprone-empty-catch): nothing is left to report with
        }
        return Exit::failure;
    }
}

std::optional<std::vector<std::string>> split_words(std::string_view line) {
    std::vector<std::string> words;
    std::string word;
    bool in_word = false;
    bool in_quote = false;
    for (const char c : line) {
        if (c == '"') {
            in_quote = !in_quote;
            in_word = true;
        } else if (!in_quote && (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f')) {
            if (in_word) {
                words.push_back(std::move(word));
                word.clear();
                in_word = false;
            }
        } else {
            word += c;
            in_word = true;
        }
    }
    if (in_quote) {
        return std::nullopt;
    }
    if (in_word) {
        words.push_back(std::move(word));
    }
    return words;
}

} // namespace ck::cli
