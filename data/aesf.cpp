// AES-256 to encrypt file 
#include "aesf.h"

// Encryption function to encrypt the file and returns void
void encryptFile(std::string &fileLocation, std::string &key) {
    // Create an instance of AES Encryption with a key and it's size and using CBC to encrypt the text using the AES encryption object
    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    // Encrypting the input file by providing the CBC Encryption object
    CryptoPP::FileSource fileSource(fileLocation.c_str(), true, new CryptoPP::StreamTransformationFilter(cbcEncryption, new CryptoPP::FileSink(fileLocation.c_str())));
}

// Decryption function to decrypt the file and returns void
void decryptFile(std::string &fileLocation, std::string &key) {
    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    CryptoPP::FileSource fileSource(fileLocation.c_str(), true, new CryptoPP::StreamTransformationFilter(cbcDecryption, new CryptoPP::FileSink(fileLocation.c_str())));
}