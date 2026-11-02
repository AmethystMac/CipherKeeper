#include "test_util.hpp"

#include <cipherkeeper/crypto/secure_buffer.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <utility>

using ck::SecureBuffer;

TEST_CASE("a default SecureBuffer is empty") {
    const SecureBuffer buffer;
    CHECK(buffer.empty());
    CHECK(buffer.data() == nullptr);
}

TEST_CASE("a new SecureBuffer is zero-filled") {
    const SecureBuffer buffer(64);
    REQUIRE(buffer.size() == 64);
    CHECK(std::ranges::all_of(buffer.bytes(), [](std::byte b) { return b == std::byte{0}; }));
}

TEST_CASE("a zero-size SecureBuffer allocates nothing") {
    const SecureBuffer buffer(0);
    CHECK(buffer.empty());
    CHECK(buffer.data() == nullptr);
}

TEST_CASE("copy_of duplicates the bytes into a new allocation") {
    const SecureBuffer original = ck::test::secret("correct horse");
    const SecureBuffer copy = SecureBuffer::copy_of(original.bytes());
    CHECK(ck::test::same_bytes(copy.bytes(), original.bytes()));
    CHECK(copy.data() != original.data());
}

TEST_CASE("moving a SecureBuffer transfers ownership") {
    SecureBuffer source = ck::test::secret("abc");
    const std::byte* const memory = source.data();

    SecureBuffer moved(std::move(source));
    CHECK(moved.data() == memory);
    CHECK(moved.size() == 3);
    CHECK(source.empty()); // NOLINT(bugprone-use-after-move): checking the moved-from state is the point

    SecureBuffer assigned = ck::test::secret("other");
    assigned = std::move(moved);
    CHECK(assigned.data() == memory);
    CHECK(moved.empty()); // NOLINT(bugprone-use-after-move)
}

TEST_CASE("reset empties the buffer") {
    SecureBuffer buffer = ck::test::secret("abc");
    buffer.reset();
    CHECK(buffer.empty());
    CHECK(buffer.data() == nullptr);
}
