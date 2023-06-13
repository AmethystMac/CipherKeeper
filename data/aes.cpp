// AES to encrypt the plaintext
#include "aes.h"

// Encrypt plaintext, returns ciphertext
std::string encryptStream(std::string &plainStream, std::string &key) {
    std::string cipherStream;

    // Create an instance of AES encryption object using CBC mode
    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipherStream));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plainStream.c_str()), plainStream.length());
    stfEncryptor.MessageEnd();

    return cipherStream;
}

// Decrypt ciphertext, returns plaintext
std::string decryptStream(std::string &cipherStream, std::string &key) {
    std::string plainStream;

    // Create an instance of AES decryption object using CBC mode
    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(plainStream));
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>(cipherStream.c_str()), cipherStream.size());
    stfDecryptor.MessageEnd();

    return plainStream;
}