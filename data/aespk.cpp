// AES to encrypt RSA Private Key
#include "aespk.h"

// Encrypt RSA private key object, returns encrypted string
std::string encryptPrivateKey(CryptoPP::RSA::PrivateKey &privateKey, std::string &key) {
    std::string serializedKey;
    privateKey.Save(CryptoPP::StringSink(serializedKey).Ref());

    // Generate a random IV (Initialization Vector)
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(iv, iv.size());

    // Create an AES encryption object
    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    // Encrypt the serialized private key
    std::string encryptedKey;
    CryptoPP::StringSource(serializedKey, true, new CryptoPP::StreamTransformationFilter(cbcEncryption, new CryptoPP::StringSink(encryptedKey)));

    // Combine the IV and encrypted key
    std::string encryptedStream;
    encryptedStream.append(reinterpret_cast<const char*>(iv.data()), iv.size());
    encryptedStream += encryptedKey;

    return encryptedStream;
}

// Encrypt RSA private key object, returns CryptoPP::RSA::PrivateKey object
CryptoPP::RSA::PrivateKey decryptPrivateKey(std::string &encryptedStream, std::string &key) {
    // Extract the IV and encrypted key from the combined encryptedStream string
    const size_t ivSize = CryptoPP::AES::BLOCKSIZE;
    const std::string iv = encryptedStream.substr(0, ivSize);
    const std::string encryptedKey = encryptedStream.substr(ivSize);

    // Prepare decryption objects
    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const CryptoPP::byte*>(key.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, reinterpret_cast<const CryptoPP::byte*>(iv.data()));

    // Decrypt the encrypted key
    std::string decryptedKey;
    CryptoPP::StringSource(encryptedKey, true, new CryptoPP::StreamTransformationFilter(cbcDecryption, new CryptoPP::StringSink(decryptedKey)));

    // Deserialize the decrypted key to obtain the private key
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::StringSource(decryptedKey, true, new CryptoPP::Base64Decoder());
    privateKey.Load(CryptoPP::StringStore(decryptedKey).Ref());

    return privateKey;
}