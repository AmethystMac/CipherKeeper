// Header file for RSA to encrypt AES Key
#pragma once

#include "cryptopp/rsa.h"
#include "cryptopp/sha3.h"
#include "cryptopp/oaep.h"
#include "cryptopp/osrng.h"
#include "cryptopp/base64.h"

std::string encryptAESKey(std::string &text, CryptoPP::RSA::PublicKey &publicKey, CryptoPP::AutoSeededRandomPool &rng);
std::string decryptAESKey(std::string &encryptedText, CryptoPP::RSA::PrivateKey &privateKey, CryptoPP::AutoSeededRandomPool &rng);