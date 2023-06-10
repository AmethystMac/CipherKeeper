#include <iostream>

#include "./data/aes.h"
#include "./data/rsak.h"

std::string encrypt(std::string &plainText, std::string &key, CryptoPP::RSA::PublicKey &publicKey, CryptoPP::AutoSeededRandomPool &rng) {
    std::string encryptedPlainText = encryptStream(plainText, key);
    std::string encryptedKey = encryptAESKey(publicKey, key, rng);

    std::string delim = "$$@-@^^-**&";
    std::string text = encryptedKey + delim + encryptedPlainText;
    std::string encryptedText = encryptStream(text, key);

    return encryptedText;
}

std::string decrypt(std::string &encryptedText, std::string &key, CryptoPP::RSA::PrivateKey &privateKey, CryptoPP::AutoSeededRandomPool &rng) {
    std::string decryptedText = decryptStream(encryptedText, key);

    std::string delim = "$$@-@^^-**&";
    int index = decryptedText.find(delim);
    if(index != std::string::npos) {
        std::string encryptedKey = decryptedText.substr(0, index);
        std::string encryptedPlainText = decryptedText.substr(index + delim.size(), decryptedText.size());

        std::string decryptedKey = decryptAESKey(privateKey, encryptedKey, rng);
        std::string decryptedPlainText = decryptStream(encryptedPlainText, key);

        return decryptedPlainText;
    }

    return "";
}

int main() {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    std::string plainText = "This is the plaintext";
    std::string key = "hello this key ";
    
    std::string encryptedText = encrypt(plainText, key, publicKey, rng);
    std::string decryptedPlainText = decrypt(encryptedText, key, privateKey, rng);


    std::string encoded1, encoded2, encoded3;
    CryptoPP::StringSource(encryptedText, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded1), false));

    std::cout << "Text: " << encoded1 << "\n\n";

    std::cout << "Decrypted Text: " << decryptedPlainText << "\n";

    return 0;
}