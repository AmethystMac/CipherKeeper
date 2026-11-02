find_package(Catch2 3 CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)

add_executable(cipherkeeper_tests
    cli_test.cpp
    core_test.cpp
    crypto_test.cpp
    item_id_test.cpp
    item_test.cpp
    secure_buffer_test.cpp
    sodium_listener.cpp
    vault_test.cpp
)
# core/src holds private headers the tests need: crypto/crypto_internal.hpp for known-answer tests, and
# storage/sqlite.hpp so vault tests can tamper with files directly.
target_include_directories(cipherkeeper_tests PRIVATE ${PROJECT_SOURCE_DIR}/core/src)
target_link_libraries(cipherkeeper_tests
    PRIVATE
        cipherkeeper::core
        cipherkeeper_cli_lib
        unofficial::sqlite3::sqlite3
        Catch2::Catch2WithMain
        ck_options
)

include(Catch)
# PRE_TEST discovery runs after vcpkg has copied dependency DLLs next to the test binary on Windows.
catch_discover_tests(cipherkeeper_tests DISCOVERY_MODE PRE_TEST)
