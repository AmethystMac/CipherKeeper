#include "aespk.h"

// Function to encrypt a private key object
std::string encryptPrivateKey(const CryptoPP::RSA::PrivateKey& privateKey, const std::string& encryptionKey) {
    std::string serializedKey;
    privateKey.Save(CryptoPP::StringSink(serializedKey).Ref());

    // Generate a random IV (Initialization Vector)
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(iv, iv.size());

    // Create an AES encryption object
    CryptoPP::AES::Encryption aesEncryption(reinterpret_cast<const CryptoPP::byte*>(encryptionKey.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    // Encrypt the serialized private key
    std::string encryptedKey;
    CryptoPP::StringSource(serializedKey, true, new CryptoPP::StreamTransformationFilter(cbcEncryption, new CryptoPP::StringSink(encryptedKey)));

    // Combine the IV and encrypted key
    std::string result;
    result.append(reinterpret_cast<const char*>(iv.data()), iv.size());
    result += encryptedKey;

    return result;
}

CryptoPP::RSA::PrivateKey decryptPrivateKey(const std::string& encryptedData, const std::string& encryptionKey) {
    // Extract the IV and encrypted key from the combined result string
    const size_t ivSize = CryptoPP::AES::BLOCKSIZE;
    const std::string iv = encryptedData.substr(0, ivSize);
    const std::string encryptedKey = encryptedData.substr(ivSize);

    // Prepare decryption objects
    CryptoPP::AES::Decryption aesDecryption(reinterpret_cast<const CryptoPP::byte*>(encryptionKey.data()), CryptoPP::AES::DEFAULT_KEYLENGTH);
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