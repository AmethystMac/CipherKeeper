// AES-256 to encrypt a file 
#include "aesf.h"

// Encrypts a file, returns void
void encryptFile(std::string &inFileLocation, std::string &outFileLocation, std::string &key) {
    // Create an instance of AES encryption object using CBC mode
    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    // Encrypting the input file by providing the CBC encryption object
    CryptoPP::FileSource fileSource(inFileLocation.c_str(), true, new CryptoPP::StreamTransformationFilter(cbcEncryption, new CryptoPP::FileSink(outFileLocation.c_str())));
}

// Decrypts a file, returns void
void decryptFile(std::string &inFileLocation, std::string &outFileLocation, std::string &key) {
    // Create an instance of AES decryption object using CBC mode
    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    // Decrypting the input file by providing the CBC decryption object
    CryptoPP::FileSource fileSource(inFileLocation.c_str(), true, new CryptoPP::StreamTransformationFilter(cbcDecryption, new CryptoPP::FileSink(outFileLocation.c_str())));
}