#include "cli.hpp"
#include "terminal.hpp"

#include <cipherkeeper/core.hpp>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    try {
        if (!ck::initialize()) {
            (void)std::fputs("ck: failed to initialize libsodium\n", stderr);
            return EXIT_FAILURE;
        }
        ck::cli::TerminalConsole console;
        const std::vector<std::string> args = ck::cli::utf8_arguments(argc, argv);
        const ck::cli::Settings settings{.default_vault = ck::cli::default_vault_path(), .kdf = {}};
        return static_cast<int>(ck::cli::run(args, console, settings));
    } catch (const std::exception& e) {
        (void)std::fputs("ck: ", stderr);
        (void)std::fputs(e.what(), stderr);
        (void)std::fputs("\n", stderr);
        return EXIT_FAILURE;
    }
}
