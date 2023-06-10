#include <iostream>
#include <fstream>
#include <string>

#include "./data/aes.h"
#include "./data/rsak.h"
#include "./data/aesf.h"

void encrypt(std::string &fileLocation, std::string &plainText, std::string &key, CryptoPP::RSA::PublicKey &publicKey, CryptoPP::AutoSeededRandomPool &rng) {
    std::string encryptedPlainText = encryptStream(plainText, key);
    std::string encryptedKey = encryptAESKey(publicKey, key, rng);

    std::string delim = "$$@-@^^-**&";
    std::string text = encryptedKey + delim + encryptedPlainText;
    std::string encryptedText = encryptStream(text, key);

    std::ofstream inputFile;
    inputFile.open(fileLocation, std::ios::out);
    
    inputFile << encryptedText;

    inputFile.close();

    encryptFile(fileLocation, key);
}

std::string decrypt(std::string &fileLocation, std::string &key, CryptoPP::RSA::PrivateKey &privateKey, CryptoPP::AutoSeededRandomPool &rng) {
    decryptFile(fileLocation, key);

    std::ifstream inputFile;
    inputFile.open(fileLocation, std::ios::in);
    
    std::string encryptedText(std::istreambuf_iterator<char>(inputFile), {});

    inputFile.close();

    std::cout << encryptedText << "\n";
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
    
    std::string inputFileLocation = "./input.txt";
    encrypt(inputFileLocation, plainText, key, publicKey, rng);

    // std::string decryptedPlainText = decrypt(inputFileLocation, key, privateKey, rng);

    // std::string encoded;
    // CryptoPP::StringSource(decryptedPlainText, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));

    // std::cout << "Text: " << encoded << "\n\n";

    // std::cout << "Decrypted Text: " << decryptedPlainText << "\n";

    return 0;
}