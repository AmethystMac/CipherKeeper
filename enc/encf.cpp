#include <iostream>

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"

void EncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& key) {
    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    CryptoPP::FileSource fileSource(inputFile.c_str(), true, 
        new CryptoPP::StreamTransformationFilter(cbcEncryption,
            new CryptoPP::FileSink(outputFile.c_str())));
}

void DecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& key) {
    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    CryptoPP::FileSource fileSource(inputFile.c_str(), true,
        new CryptoPP::StreamTransformationFilter(cbcDecryption,
            new CryptoPP::FileSink(outputFile.c_str())));
}

int main() {
    std::string inputFile = "input.txt";
    std::string encryptedFile = "encrypted.bin";
    std::string decryptedFile = "decrypted.txt";
    std::string key = "mysecretpassword";

    EncryptFile(inputFile, encryptedFile, key);
    DecryptFile(encryptedFile, decryptedFile, key);

    std::cout << "File encryption and decryption completed." << std::endl;

    return 0;
}
