// Header file for RSA to encrypt AES Key
#pragma once

#include <iostream>

#include "cryptopp/rsa.h"
#include "cryptopp/osrng.h"
#include "cryptopp/base64.h"

std::string encryptAESKey(CryptoPP::RSA::PublicKey &publicKey, std::string &key, CryptoPP::AutoSeededRandomPool &rng);
std::string decryptAESKey(CryptoPP::RSA::PrivateKey &privateKey, std::string &encryptedKey, CryptoPP::AutoSeededRandomPool &rng);