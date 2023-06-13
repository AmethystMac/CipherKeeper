#include <iostream>
#include <fstream>
#include <string>

#include "./data/aes.h"
#include "./data/rsak.h"
#include "./data/aespk.h"
#include "./data/aesf.h"

void encrypt(std::string &inFileLocation, std::string &outFileLocation, std::string &plainText, std::string &key) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 2048);

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    std::string randKey;
    randKey.resize(CryptoPP::AES::DEFAULT_KEYLENGTH);
    rng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(randKey.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);

    std::string encryptedPlainText = encryptStream(plainText, randKey);
    std::string encryptedKey = encryptAESKey(randKey, publicKey);

    std::string k = encryptedPlainText + encryptedKey;
    std::string encryptedPrivateKey = encryptPrivateKey(privateKey, k);

    std::string delim1 = "$$@-@^^-**&", delim2 = "&##-%%!-!((";
    std::string text = encryptedKey + delim1 + encryptedPlainText + delim2 + encryptedPrivateKey;
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

    std::string delim1 = "$$@-@^^-**&", delim2 = "&##-%%!-!((";
    int index1 = decryptedText.find(delim1), index2 = decryptedText.find(delim2);
    if(index1 != std::string::npos) {
        std::string encryptedKey = decryptedText.substr(0, index1);
        std::string encryptedPlainText = decryptedText.substr(index1 + delim1.size(),  index2 - (index1 + delim1.size()));
        std::string encryptedPrivateKey = decryptedText.substr(index2 + delim2.size(), decryptedText.size() - (index2 + delim2.size()));
    
        std::string k = encryptedPlainText + encryptedKey;
        CryptoPP::RSA::PrivateKey privateKey = decryptPrivateKey(encryptedPrivateKey, k);
        std::string decryptedKey = decryptAESKey(encryptedKey, privateKey);
        std::string decryptedPlainText = decryptStream(encryptedPlainText, decryptedKey);

        return decryptedPlainText;
    }

    return "";
}

int main() {
    std::string plainText = "This is the plaintext";
    std::string key = "this key is big";
    
    std::string inputFileLocation = "./file1.txt", encryptFileLocation = "./file2.bin", decryptFileLocation = "./file3.txt";

    // encrypt(inputFileLocation, encryptFileLocation, plainText, key);
    std::string decryptedPlainText = decrypt(encryptFileLocation, decryptFileLocation, key);

    // std::string encoded;
    // CryptoPP::StringSource(decryptedPlainText, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));

    // std::cout << "Text: " << encoded << "\n\n";

    std::cout << "Decrypted Text: " << decryptedPlainText << "\n";

    return 0;
}