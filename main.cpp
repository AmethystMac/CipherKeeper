#include <iostream>

#include "./data/aes.h"
#include "./data/rsak.h"

int main() {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    std::string plainText = "this is matthew";
    std::string key = "hello this key ";

    std::string encryptedText = encryptStream(plainText, key);

    std::string encryptedKey = encryptAESKey(publicKey, key, rng);

    std::string decryptedKey = decryptAESKey(privateKey, encryptedKey, rng);

    std::string decryptedText = decryptStream(encryptedText, key);

    std::string encoded1, encoded2;
    CryptoPP::StringSource(encryptedText, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded1), false));
    CryptoPP::StringSource(encryptedKey, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded2), false));

    std::cout << "Original Text: " << plainText << "\n";
    std::cout << "Original Key: " << key << "\n\n";

    std::cout << "Encrypted Text: " << encoded1 << "\n";
    std::cout << "Encrypted Key (Base64): " << encoded2 << std::endl;
    std::cout << "Decrypted Key: " << decryptedKey << std::endl;
    std::cout << "Decrypted Text: " << decryptedText << "\n";

    return 0;
}