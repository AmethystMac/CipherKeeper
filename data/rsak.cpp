// RSA to encrypt AES Key

#include "rsak.h"

// Encrypting AES Key
std::string encryptAESKey(std::string &text, CryptoPP::RSA::PublicKey &publicKey, CryptoPP::AutoSeededRandomPool &rng) {
    // Create a SHA-3 hash function object
    CryptoPP::SHA3_256 hash;

    // Hash the input text using SHA-3
    std::string hashedText;
    CryptoPP::StringSource(text, true, new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(hashedText)));

    // Create a RSA Encryption object with OAEP padding
    CryptoPP::RSAES_OAEP_SHA_Encryptor rsaEncryptor(publicKey);

    std::string encrypted;
    CryptoPP::StringSource(hashedText, true, new CryptoPP::PK_EncryptorFilter(rng, rsaEncryptor, new CryptoPP::StringSink(encrypted)));

    return encrypted;
}

// Decrypting AES Key
std::string decryptAESKey(std::string &encryptedText, CryptoPP::RSA::PrivateKey &privateKey, CryptoPP::AutoSeededRandomPool &rng) {
    // Create a SHA3_256 hash function object
    CryptoPP::SHA3_256 hash;

    // Create a RSA Decryption object with OAEP padding and SHA3_256 hash function
    CryptoPP::RSAES_OAEP_SHA_Decryptor rsaDecryptor(privateKey);

    // Decrypt the encrypted text
    std::string ecryptedHash;
    CryptoPP::StringSource(encryptedText, true, new CryptoPP::PK_DecryptorFilter(rng, rsaDecryptor, new CryptoPP::StringSink(ecryptedHash)));

    // Hash the ecryptedHash text using SHA3_256
    std::string decrypted;
    CryptoPP::StringSource(ecryptedHash, true, new CryptoPP::HashFilter(hash, new CryptoPP::StringSink(decrypted)));

    return decrypted;
}