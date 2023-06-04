#include "aes.h"

void encryptStream(std::string &plainStream, std::string &encryptedStream, std::string &key) {
    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(encryptedStream));
    stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plainStream.c_str()), plainStream.length());
    stfEncryptor.MessageEnd();
}

void decryptStream(std::string &encryptedStream, std::string &decryptedStream, std::string &key) {
    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, reinterpret_cast<const CryptoPP::byte*>(key.data()));

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedStream));
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>(encryptedStream.c_str()), encryptedStream.size());
    stfDecryptor.MessageEnd();
}

int main() {
    std::string plainText = "bro can you do something cooooool?????AS?DAS?DQWasa";
    std::string encryptedText;
    std::string decryptedText;
    std::string key = "mysecretpassword";

    std::cout << plainText << "\n";

    encryptStream(plainText, encryptedText, key);

    for(int i = 0; i < encryptedText.size(); i++) {
        std::cout << std::hex << (0xFF & static_cast<CryptoPP::byte>(encryptedText[i]));
    }
    std::cout << "\n";

    decryptStream(encryptedText, decryptedText, key);

    std::cout << decryptedText << "\n";

    return 0;
}