#include <cipherkeeper/core.hpp>

#include <cstdlib>
#include <exception>
#include <iostream>

int main() {
    try {
        if (!ck::initialize()) {
            std::cerr << "ck: failed to initialize libsodium\n";
            return EXIT_FAILURE;
        }

        const ck::LibraryVersions libs = ck::library_versions();
        std::cout << "ck " << ck::version() << " (libsodium " << libs.sodium << ", SQLite " << libs.sqlite << ")\n"
                  << "Vault commands arrive in Phase 1.\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "ck: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
}
