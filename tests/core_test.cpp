#include <cipherkeeper/core.hpp>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("initialize succeeds and can be called again") {
    REQUIRE(ck::initialize());
    REQUIRE(ck::initialize());
}

TEST_CASE("version matches the CMake project version") {
    CHECK(ck::version() == "0.1.0");
}

TEST_CASE("library versions are reported") {
    REQUIRE(ck::initialize());
    const ck::LibraryVersions libs = ck::library_versions();
    CHECK_FALSE(libs.sodium.empty());
    CHECK_FALSE(libs.sqlite.empty());
}
