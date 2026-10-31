#include "crypto/crypto_internal.hpp"
#include "test_util.hpp"

#include <cipherkeeper/crypto/crypto.hpp>

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace crypto = ck::crypto;
using ck::SecureBuffer;
using ck::test::bytes_of;
using ck::test::from_hex;
using ck::test::same_bytes;
using ck::test::secret;
using ck::test::secret_from_hex;

namespace {

// Cheap Argon2id settings so the tests run quickly. Never use these for a real vault.
constexpr crypto::KdfParams fast_kdf{.ops_limit = 1, .mem_limit = std::size_t{1} << 20U};

crypto::Salt salt_from_hex(std::string_view hex) {
    const std::vector<std::byte> bytes = from_hex(hex);
    REQUIRE(bytes.size() == crypto::salt_size);
    crypto::Salt salt{};
    std::ranges::copy(bytes, salt.begin());
    return salt;
}

} // namespace

// ---- Random ------------------------------------------------------------------------------------------------------

TEST_CASE("random keys and salts have the right size and differ") {
    const SecureBuffer a = crypto::random_key();
    const SecureBuffer b = crypto::random_key();
    REQUIRE(a.size() == crypto::key_size);
    CHECK_FALSE(same_bytes(a.bytes(), b.bytes()));
    CHECK(crypto::random_salt() != crypto::random_salt());
}

// ---- Constant-time comparison -------------------------------------------------------------------------------------

TEST_CASE("constant_time_equal compares contents and lengths") {
    const std::vector<std::byte> abc = from_hex("616263");
    CHECK(crypto::constant_time_equal(abc, from_hex("616263")));
    CHECK_FALSE(crypto::constant_time_equal(abc, from_hex("616264")));
    CHECK_FALSE(crypto::constant_time_equal(abc, from_hex("6162")));
    CHECK(crypto::constant_time_equal({}, {}));
}

// ---- Argon2id -----------------------------------------------------------------------------------------------------

TEST_CASE("Argon2id matches libsodium's known-answer vector") {
    // tests[0] in libsodium test/default/pwhash_argon2id.c, with its output from pwhash_argon2id.exp. tv() reads
    // only the first crypto_pwhash_SALTBYTES (16) bytes of the listed salt.
    const std::vector<std::byte> password =
        from_hex("a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae065577a928febd9b1973a5a95073acdbe"
                 "b6a030cfc0d79caa2dc5cd011cef02c08da232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6"
                 "f58d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6");
    REQUIRE(password.size() == 127);
    const crypto::Salt salt = salt_from_hex("5541fbc995d5c197ba290346d2c559de");
    const std::vector<std::byte> expected =
        from_hex("18acec5d6507739f203d1f5d9f1d862f7c2cdac4f19d2bdff64487e60d969e3ced615337b9eec6ac4461c6ca07f093974"
                 "1e57c24d0005c7ea171a0ee1e7348249d135b38f222e4dad7b9a033ed83f5ca27277393e316582033c74affe2566a2bea4"
                 "7f91f0fd9fe49ece7e1f79f3ad6e9b23e0277c8ecc4b313225748dd2a80f5679534a0700e246a79a49b3f74eb89ec6205f"
                 "e1eeb941c73b1fcf1");
    REQUIRE(expected.size() == 155);

    std::vector<std::byte> out(expected.size());
    crypto::detail::argon2id(out, password, salt, {.ops_limit = 5, .mem_limit = 7256678});
    CHECK(same_bytes(out, expected));
}

TEST_CASE("the default KDF parameters are 64 MiB and 3 passes") {
    const crypto::KdfParams defaults;
    CHECK(defaults.ops_limit == 3);
    CHECK(defaults.mem_limit == std::size_t{64} * 1024 * 1024);
}

TEST_CASE("derive_master_key is deterministic and depends on every input") {
    const SecureBuffer password = secret("throwaway-test-password");
    const crypto::Salt salt = salt_from_hex("000102030405060708090a0b0c0d0e0f");

    const SecureBuffer key = crypto::derive_master_key(password, salt, fast_kdf);
    REQUIRE(key.size() == crypto::key_size);
    CHECK(same_bytes(key.bytes(), crypto::derive_master_key(password, salt, fast_kdf).bytes()));

    SECTION("a different password gives a different key") {
        const SecureBuffer other = crypto::derive_master_key(secret("throwaway-test-passwore"), salt, fast_kdf);
        CHECK_FALSE(same_bytes(key.bytes(), other.bytes()));
    }
    SECTION("a different salt gives a different key") {
        crypto::Salt other_salt = salt;
        other_salt[0] ^= std::byte{1};
        CHECK_FALSE(same_bytes(key.bytes(), crypto::derive_master_key(password, other_salt, fast_kdf).bytes()));
    }
    SECTION("different parameters give a different key") {
        const crypto::KdfParams more_passes{.ops_limit = 2, .mem_limit = fast_kdf.mem_limit};
        CHECK_FALSE(same_bytes(key.bytes(), crypto::derive_master_key(password, salt, more_passes).bytes()));
    }
}

TEST_CASE("derive_master_key accepts an empty password") {
    // Password policy belongs to the vault layer; the KDF itself must not crash on empty input.
    const SecureBuffer key = crypto::derive_master_key(SecureBuffer{}, crypto::random_salt(), fast_kdf);
    CHECK(key.size() == crypto::key_size);
}

TEST_CASE("derive_master_key rejects out-of-range parameters") {
    const SecureBuffer password = secret("throwaway-test-password");
    const crypto::Salt salt = crypto::random_salt();
    CHECK_THROWS_AS(crypto::derive_master_key(password, salt, {.ops_limit = 0, .mem_limit = fast_kdf.mem_limit}),
                    std::invalid_argument);
    CHECK_THROWS_AS(crypto::derive_master_key(password, salt, {.ops_limit = 1, .mem_limit = 1024}),
                    std::invalid_argument);
}

// ---- HKDF ---------------------------------------------------------------------------------------------------------

TEST_CASE("HKDF-Expand matches RFC 5869 test case 1") {
    const SecureBuffer prk = secret_from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    const std::vector<std::byte> info_bytes = from_hex("f0f1f2f3f4f5f6f7f8f9");
    const std::string info(reinterpret_cast<const char*>(info_bytes.data()), info_bytes.size());
    const std::vector<std::byte> expected =
        from_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    const SecureBuffer okm = crypto::hkdf_expand(prk, info, expected.size());
    CHECK(same_bytes(okm.bytes(), expected));
}

TEST_CASE("hkdf_expand rejects bad inputs") {
    const SecureBuffer prk = crypto::random_key();
    CHECK_THROWS_AS(crypto::hkdf_expand(prk, "label", 0), std::invalid_argument);
    CHECK_THROWS_AS(crypto::hkdf_expand(prk, "label", (255 * 32) + 1), std::invalid_argument);
    CHECK_THROWS_AS(crypto::hkdf_expand(secret("short"), "label", 32), std::invalid_argument);
}

TEST_CASE("derive_subkeys gives two independent, deterministic keys") {
    const SecureBuffer master = crypto::random_key();
    const crypto::DerivedKeys keys = crypto::derive_subkeys(master);
    REQUIRE(keys.auth_key.size() == crypto::key_size);
    REQUIRE(keys.kek.size() == crypto::key_size);
    CHECK_FALSE(same_bytes(keys.auth_key.bytes(), keys.kek.bytes()));
    CHECK_FALSE(same_bytes(keys.kek.bytes(), master.bytes()));

    const crypto::DerivedKeys again = crypto::derive_subkeys(master);
    CHECK(same_bytes(keys.auth_key.bytes(), again.auth_key.bytes()));
    CHECK(same_bytes(keys.kek.bytes(), again.kek.bytes()));
}

// ---- XChaCha20-Poly1305 -------------------------------------------------------------------------------------------

TEST_CASE("XChaCha20-Poly1305 matches draft-irtf-cfrg-xchacha-03 A.3.1") {
    const SecureBuffer key = secret_from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const std::vector<std::byte> nonce_bytes = from_hex("404142434445464748494a4b4c4d4e4f5051525354555657");
    const std::span<const std::byte, crypto::nonce_size> nonce(nonce_bytes.data(), crypto::nonce_size);
    const std::vector<std::byte> aad = from_hex("50515253c0c1c2c3c4c5c6c7");
    const std::string_view plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
                                       "for the future, sunscreen would be it.";
    REQUIRE(plaintext.size() == 114);

    std::vector<std::byte> expected = nonce_bytes;
    const std::vector<std::byte> ciphertext_and_tag =
        from_hex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39"
                 "ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
                 "21f9664c97637da9768812f615c68b13b52e"
                 "c0875924c1c7987947deafd8780acf49");
    expected.insert(expected.end(), ciphertext_and_tag.begin(), ciphertext_and_tag.end());

    const std::vector<std::byte> sealed = crypto::detail::seal_with_nonce(key, nonce, bytes_of(plaintext), aad);
    CHECK(same_bytes(sealed, expected));

    const std::optional<SecureBuffer> opened = crypto::open(key, expected, aad);
    REQUIRE(opened.has_value());
    CHECK(same_bytes(opened->bytes(), bytes_of(plaintext)));
}

TEST_CASE("seal and open round-trip") {
    const SecureBuffer key = crypto::random_key();
    const std::span<const std::byte> ad = bytes_of("item-1|vault-1|v1");

    SECTION("with a payload") {
        const std::span<const std::byte> plaintext = bytes_of("hunter2 but longer");
        const std::vector<std::byte> sealed = crypto::seal(key, plaintext, ad);
        REQUIRE(sealed.size() == plaintext.size() + crypto::sealed_overhead);
        const std::optional<SecureBuffer> opened = crypto::open(key, sealed, ad);
        REQUIRE(opened.has_value());
        CHECK(same_bytes(opened->bytes(), plaintext));
    }
    SECTION("with an empty payload and no associated data") {
        const std::vector<std::byte> sealed = crypto::seal(key, {}, {});
        REQUIRE(sealed.size() == crypto::sealed_overhead);
        const std::optional<SecureBuffer> opened = crypto::open(key, sealed, {});
        REQUIRE(opened.has_value());
        CHECK(opened->empty());
    }
}

TEST_CASE("every seal uses a fresh nonce") {
    const SecureBuffer key = crypto::random_key();
    const std::vector<std::byte> a = crypto::seal(key, bytes_of("same"), {});
    const std::vector<std::byte> b = crypto::seal(key, bytes_of("same"), {});
    CHECK_FALSE(same_bytes(std::span(a).first(crypto::nonce_size), std::span(b).first(crypto::nonce_size)));
    CHECK_FALSE(same_bytes(a, b));
}

TEST_CASE("open rejects a wrong key") {
    const std::vector<std::byte> sealed = crypto::seal(crypto::random_key(), bytes_of("secret"), {});
    CHECK_FALSE(crypto::open(crypto::random_key(), sealed, {}).has_value());
}

TEST_CASE("open rejects wrong associated data") {
    const SecureBuffer key = crypto::random_key();
    const std::vector<std::byte> sealed = crypto::seal(key, bytes_of("secret"), bytes_of("item-1|vault-1|v1"));
    CHECK_FALSE(crypto::open(key, sealed, bytes_of("item-2|vault-1|v1")).has_value());
    CHECK_FALSE(crypto::open(key, sealed, {}).has_value());
}

TEST_CASE("open rejects a single flipped bit anywhere in the sealed blob") {
    const SecureBuffer key = crypto::random_key();
    const std::vector<std::byte> sealed = crypto::seal(key, bytes_of("twenty bytes of data"), bytes_of("ad"));
    for (std::size_t i = 0; i < sealed.size(); ++i) {
        std::vector<std::byte> tampered = sealed;
        tampered[i] ^= std::byte{0x01};
        INFO("flipped byte " << i);
        CHECK_FALSE(crypto::open(key, tampered, bytes_of("ad")).has_value());
    }
}

TEST_CASE("open rejects truncated and extended input") {
    const SecureBuffer key = crypto::random_key();
    const std::vector<std::byte> sealed = crypto::seal(key, bytes_of("some data"), {});
    for (std::size_t length = 0; length < sealed.size(); ++length) {
        INFO("length " << length);
        CHECK_FALSE(crypto::open(key, std::span(sealed).first(length), {}).has_value());
    }
    std::vector<std::byte> extended = sealed;
    extended.push_back(std::byte{0});
    CHECK_FALSE(crypto::open(key, extended, {}).has_value());
}

TEST_CASE("seal and open reject keys of the wrong size") {
    const SecureBuffer short_key(16);
    CHECK_THROWS_AS(crypto::seal(short_key, bytes_of("x"), {}), std::invalid_argument);
    const std::vector<std::byte> sealed = crypto::seal(crypto::random_key(), bytes_of("x"), {});
    CHECK_THROWS_AS(crypto::open(short_key, sealed, {}), std::invalid_argument);
}

// ---- Key hierarchy ------------------------------------------------------------------------------------------------

TEST_CASE("the KEK wraps a vault key and a wrong password fails to unwrap it") {
    const crypto::Salt salt = crypto::random_salt();
    const std::span<const std::byte> ad = bytes_of("local-vault-key|v1");

    const SecureBuffer vault_key = crypto::random_key();
    const crypto::DerivedKeys keys =
        crypto::derive_subkeys(crypto::derive_master_key(secret("Tulip-Orbit-Canyon-42"), salt, fast_kdf));
    const std::vector<std::byte> wrapped = crypto::seal(keys.kek, vault_key.bytes(), ad);

    SECTION("the right password unwraps it") {
        const crypto::DerivedKeys again =
            crypto::derive_subkeys(crypto::derive_master_key(secret("Tulip-Orbit-Canyon-42"), salt, fast_kdf));
        const std::optional<SecureBuffer> unwrapped = crypto::open(again.kek, wrapped, ad);
        REQUIRE(unwrapped.has_value());
        CHECK(same_bytes(unwrapped->bytes(), vault_key.bytes()));
    }
    SECTION("a wrong password fails the tag check") {
        const crypto::DerivedKeys wrong =
            crypto::derive_subkeys(crypto::derive_master_key(secret("Tulip-Orbit-Canyon-43"), salt, fast_kdf));
        CHECK_FALSE(crypto::open(wrong.kek, wrapped, ad).has_value());
    }
    SECTION("the Auth Key can't unwrap it") {
        CHECK_FALSE(crypto::open(keys.auth_key, wrapped, ad).has_value());
    }
}
