#include <iostream>
#include <fstream>
#include <string>

#include "./data/aes.h"
#include "./data/rsak.h"
#include "./data/aesf.h"

void encrypt(std::string &inFileLocation, std::string &outFileLocation, std::string &plainText, std::string &key) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    std::string encryptedPlainText = encryptStream(plainText, key);
    std::string encryptedKey = encryptAESKey(publicKey, key, rng);

    std::string delim1 = "$$@-@^^-**&", delim2 = "&##-%%!-!((";
    std::string text = encryptedKey + delim1 + encryptedPlainText;
    std::string encryptedText = encryptStream(text, key);

    std::ofstream inputFile;
    inputFile.open(inFileLocation, std::ios::out);
    
    inputFile << encryptedText;

    inputFile.close();

    encryptFile(inFileLocation, outFileLocation, key);

    //std::remove(inFileLocation.c_str());
}

std::string decrypt(std::string &inFileLocation, std::string &outFileLocation, std::string &key) {
    CryptoPP::AutoSeededRandomPool rng;

    decryptFile(inFileLocation, outFileLocation, key);

    //std::remove(inFileLocation.c_str());

    std::ifstream inputFile;
    inputFile.open(outFileLocation, std::ios::in);
    
    std::string encryptedText(std::istreambuf_iterator<char>(inputFile), {});

    inputFile.close();

    std::string decryptedText = decryptStream(encryptedText, key);

    std::string delim1 = "$$@-@^^-**&", delim2 = "";
    int index = decryptedText.find(delim1);
    if(index != std::string::npos) {
        std::string encryptedKey = decryptedText.substr(0, index);
        std::string encryptedPlainText = decryptedText.substr(index + delim1.size(), decryptedText.size());

        std::cout << encryptedKey << "\n";
        std::string decryptedKey = decryptAESKey(privateKey, encryptedKey, rng);
        std::string decryptedPlainText = decryptStream(encryptedPlainText, key);

        return decryptedPlainText;
    }

    return "";
}

int main() {
    std::string plainText = "This is the plaintext";
    std::string key = "hello this key ";
    
    std::string inputFileLocation = "./file1.txt", encryptFileLocation = "./file2.bin", decryptFileLocation = "./file3.txt";
    encrypt(inputFileLocation, encryptFileLocation, plainText, key);

    std::string decryptedPlainText = decrypt(encryptFileLocation, decryptFileLocation, key);

    // std::string encoded;
    // CryptoPP::StringSource(decryptedPlainText, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));

    // std::cout << "Text: " << encoded << "\n\n";

    std::cout << "Decrypted Text: " << decryptedPlainText << "\n";

    return 0;
}