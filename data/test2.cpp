#include <cryptopp/rsa.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>

using namespace CryptoPP;

void encryptPrivateKey(const std::string& key, const RSA::PrivateKey& privateKey, const std::string& outputFile)
{
    AutoSeededRandomPool rng;
    SecByteBlock iv(AES::BLOCKSIZE);
    rng.GenerateBlock(iv, iv.size());

    // Serialize the private key
    ByteQueue privateKeyQueue;
    privateKey.Save(privateKeyQueue);
    std::string serializedPrivateKey;
    StringSink serializedPrivateKeySink(serializedPrivateKey);
    privateKeyQueue.TransferTo(serializedPrivateKeySink);
    serializedPrivateKeySink.MessageEnd();

    // Encrypt the serialized private key
    SecByteBlock encryptedPrivateKey;
    CFB_Mode<AES>::Encryption cfbEncryption(reinterpret_cast<const byte*>(key.data()), key.size(), iv);
    StringSource(serializedPrivateKey, true, new StreamTransformationFilter(cfbEncryption, new ArraySink(encryptedPrivateKey), StreamTransformationFilter::ZEROS_PADDING));

    // Save the IV and encrypted private key to a file
    std::string ivAndEncryptedKey(reinterpret_cast<const char*>(iv.data()), iv.size());
    ivAndEncryptedKey += std::string(reinterpret_cast<const char*>(encryptedPrivateKey.data()), encryptedPrivateKey.size());
    StringSource(ivAndEncryptedKey, true, new FileSink(outputFile.c_str()));
}

RSA::PrivateKey decryptPrivateKey(const std::string& key, const std::string& inputFile)
{
    std::string ivAndEncryptedKey;
    FileSource(inputFile.c_str(), true, new StringSink(ivAndEncryptedKey));

    SecByteBlock iv(AES::BLOCKSIZE);
    SecByteBlock encryptedPrivateKey(ivAndEncryptedKey.size() - AES::BLOCKSIZE);
    memcpy(iv, ivAndEncryptedKey.data(), AES::BLOCKSIZE);
    memcpy(encryptedPrivateKey, ivAndEncryptedKey.data() + AES::BLOCKSIZE, ivAndEncryptedKey.size() - AES::BLOCKSIZE);

    // Decrypt the encrypted private key
    SecByteBlock decryptedPrivateKey(encryptedPrivateKey.size());
    CFB_Mode<AES>::Decryption cfbDecryption(reinterpret_cast<const byte*>(key.data()), key.size(), iv);
    StringSource(encryptedPrivateKey, true, new StreamTransformationFilter(cfbDecryption, new ArraySink(decryptedPrivateKey), StreamTransformationFilter::ZEROS_PADDING));

    // Deserialize the decrypted private key
    RSA::PrivateKey privateKey;
    ByteQueue privateKeyQueue;
    StringSource(decryptedPrivateKey, true, new ArraySink(privateKeyQueue));
    privateKey.Load(privateKeyQueue);

    return privateKey;
}