find_package(Catch2 3 CONFIG REQUIRED)

add_executable(cipherkeeper_tests
    core_test.cpp
)
target_link_libraries(cipherkeeper_tests PRIVATE cipherkeeper::core Catch2::Catch2WithMain ck_options)

include(Catch)
# PRE_TEST discovery runs after vcpkg has copied dependency DLLs next to the test binary on Windows.
catch_discover_tests(cipherkeeper_tests DISCOVERY_MODE PRE_TEST)
