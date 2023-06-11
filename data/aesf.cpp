// AES-256 to encrypt file 
#include "aesf.h"

// Encrypts the file, returns void
void encryptFile(std::string &inFileLocation, std::string &outFileLocation, std::string &key) {
    // Create an instance of AES Encryption with a key and it's size and using CBC to encrypt the text using the AES encryption object
    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    // Encrypting the input file by providing the CBC Encryption object
    CryptoPP::FileSource fileSource(inFileLocation.c_str(), true, new CryptoPP::StreamTransformationFilter(cbcEncryption, new CryptoPP::FileSink(outFileLocation.c_str())));
}

// Decrypts the file, returns void
void decryptFile(std::string &inFileLocation, std::string &outFileLocation, std::string &key) {
    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    CryptoPP::FileSource fileSource(inFileLocation.c_str(), true, new CryptoPP::StreamTransformationFilter(cbcDecryption, new CryptoPP::FileSink(outFileLocation.c_str())));
}