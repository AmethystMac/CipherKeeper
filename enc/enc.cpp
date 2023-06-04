#include "enc.h"

void encryptPassword() {

}

// Function to verify the saved password against the one 
bool verifyPassword(const std::string& password, const std::string& storedSalt, const std::string& storedHash) {
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
    CryptoPP::SecByteBlock derivedKey(storedHash.size());

    // Decode the stored salt and stored hash
    CryptoPP::StringSource storedSaltSource(storedSalt, true, new CryptoPP::HexDecoder);
    CryptoPP::StringSource storedHashSource(storedHash, true, new CryptoPP::HexDecoder);

    // Retrieve the salt value
    CryptoPP::SecByteBlock salt(storedSalt.size());
    storedSaltSource.Get(salt, salt.size());

    // Derive the key using the retrieved salt
    pbkdf2.DeriveKey(derivedKey, derivedKey.size(), 0x00, reinterpret_cast<const cbyte*>(password.data()), password.length(), salt.data(), salt.size(), 10000);

    // std::cout << storedHashSource.to;

    // Compare the derived key with the stored hash
    return CryptoPP::VerifyBufsEqual(derivedKey.data(), reinterpret_cast<const cbyte*>(storedHash.data()), derivedKey.size());
}

int main() {
    CryptoPP::AutoSeededRandomPool rng;

    // Generate a random salt
    // CryptoPP::SecByteBlock salt;
    std::string salt = "LMFAO";
    // rng.GenerateBlock(salt, salt.size());

    // Set the number of iterations
    int iterations = 10000;

    // Set the desired derived key size
    int derivedKeySize = 32; // 32 bytes = 256 bits

    // The password and its length
    std::string password = "password";
    size_t passwordLength = password.length();

    // Derive the key using PBKDF2
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
    CryptoPP::SecByteBlock derivedKey(derivedKeySize);
    pbkdf2.DeriveKey(derivedKey, derivedKey.size(), 0x00, reinterpret_cast<const cbyte*>(password.data()), passwordLength, reinterpret_cast<CryptoPP::byte*>(salt.data()), salt.size(), iterations);

    // Print the derived key as hex
    std::string encodedKey;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(encodedKey));
    encoder.Put(derivedKey.data(), derivedKey.size());
    encoder.MessageEnd();

    std::cout << "Derived Key: " << encodedKey << std::endl;

    std::cout << (verifyPassword("password", "LMFAO", "71CDFF54D26A529E9912AC133D0FB06D55A5FD3C3402E0C618C42BBF06141D74") ? "TRUE" : "FALSE");

    return 0;
}