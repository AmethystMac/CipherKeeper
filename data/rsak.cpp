// RSA to encrypt AES Key
#include "rsak.h"

// Encrypt AES key using RSA with SHA256 hash function
std::string encryptAESKey(std::string& plaintext, CryptoPP::RSA::PublicKey& publicKey) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string ciphertext;

    // Create RSA encryption object
    CryptoPP::RSAES_OAEP_SHA256_Encryptor rsaEncryptor(publicKey);
    CryptoPP::StringSource(plaintext, true, new CryptoPP::PK_EncryptorFilter(rng, rsaEncryptor, new CryptoPP::StringSink(ciphertext)));

    return ciphertext;
}

// Decrypt AES key using RSA with SHA256 hash function
std::string decryptAESKey(std::string& ciphertext, CryptoPP::RSA::PrivateKey& privateKey) {
    CryptoPP::AutoSeededRandomPool rng;
    std::string plaintext;

    // Create RSA decryption object
    CryptoPP::RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privateKey);
    CryptoPP::StringSource(ciphertext, true, new CryptoPP::PK_DecryptorFilter(rng, rsaDecryptor, new CryptoPP::StringSink(plaintext)));

    return plaintext;
}