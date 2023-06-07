#include "aes.h"

std::string encryptStream(std::string &plainStream, std::string &key) {
    std::string encryptedStream;

    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(encryptedStream));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plainStream.c_str()), plainStream.length());
    stfEncryptor.MessageEnd();

    return encryptedStream;
}

std::string decryptStream(std::string &encryptedStream, std::string &key) {
    std::string decryptedStream;

    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedStream));
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>(encryptedStream.c_str()), encryptedStream.size());
    stfDecryptor.MessageEnd();

    return decryptedStream;
}

// int main() {
//     std::string plainText = "hmmmm";
//     std::string key = "mysecretpassword";

//     std::cout << plainText << "\n";

//     std::string encryptedText = encryptStream(plainText, key);

//     std::string encoded;
//     CryptoPP::StringSource(encryptedText, true, new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));

//     std::cout << encoded << "\n";

//     std::string decryptedText = decryptStream(encryptedText, key);

//     std::cout << decryptedText << "\n";

//     return 0;
// }