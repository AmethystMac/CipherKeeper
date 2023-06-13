// Header file for RSA to encrypt AES Key
#pragma once

#include "cryptopp/rsa.h"
#include "cryptopp/oaep.h"
#include "cryptopp/osrng.h"
#include "cryptopp/base64.h"

std::string encryptAESKey(std::string &plaintext, CryptoPP::RSA::PublicKey &publicKey);
std::string decryptAESKey(std::string &ciphertext, CryptoPP::RSA::PrivateKey &privateKey);