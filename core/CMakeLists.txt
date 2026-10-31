find_package(unofficial-sodium CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)

# Sources are grouped by feature, mirrored in include/cipherkeeper/:
#   crypto/   key derivation, encryption, secure memory
#   model/    vault item types
#   storage/  the vault file and its SQLite access
add_library(cipherkeeper_core
    src/core.cpp
    src/crypto/crypto.cpp
    src/crypto/secure_buffer.cpp
    src/model/item_id.cpp
    src/storage/sqlite.cpp
    src/storage/vault.cpp
)
add_library(cipherkeeper::core ALIAS cipherkeeper_core)

# include/ is the public API: anything linking core can use it. src/ also holds private headers (e.g.
# storage/sqlite.hpp) that only core itself sees, so front ends can't bypass the public API.
target_include_directories(cipherkeeper_core
    PUBLIC include
    PRIVATE src
)
target_compile_definitions(cipherkeeper_core PRIVATE CK_VERSION="${PROJECT_VERSION}")
target_link_libraries(cipherkeeper_core
    PRIVATE
        unofficial-sodium::sodium
        unofficial::sqlite3::sqlite3
        ck_options
)
