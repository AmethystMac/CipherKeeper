// RSA to encrypt AES Key

#include "enckrsa.h"

// Encrypting AES Key
std::string encryptAESKey(CryptoPP::RSA::PublicKey &publicKey, std::string &key, CryptoPP::AutoSeededRandomPool &rng) {
    CryptoPP::RSAES_OAEP_SHA_Encryptor rsaEncryptor(publicKey);
    std::string encrypted;
    CryptoPP::StringSource(key, true, new CryptoPP::PK_EncryptorFilter(rng, rsaEncryptor, new CryptoPP::StringSink(encrypted)));

    return encrypted;
}

// Decrypting AES Key
std::string decryptAESKey(CryptoPP::RSA::PrivateKey &privateKey, std::string &encryptedKey, CryptoPP::AutoSeededRandomPool &rng) {
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    std::string decrypted;
    CryptoPP::StringSource(encryptedKey, true, new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decrypted)));

    return decrypted;
}

int main() {
    // Generate RSA key pair
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);

    // Generate public and private keys
    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    // Message to encrypt
    std::string key = "AYYYY THIS SHIT IS FREAKIN COOL";

    std::string encryptedKey = encryptAESKey(publicKey, key, rng);
    std::string decryptedKey = decryptAESKey(privateKey, encryptedKey, rng);

    // Base64 encoding
    std::string encoded;
    CryptoPP::StringSource(decryptedKey, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));

    // Output
    std::cout << "Original Message: " << key << std::endl;
    std::cout << "Encrypted Message (Base64): " << encoded << std::endl;
    std::cout << "Decrypted Message: " << decryptedKey << std::endl;

    return 0;
}