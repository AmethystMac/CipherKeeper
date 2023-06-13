// Header for AES to encrypt RSA Private Key
#pragma once

#include "cryptopp/aes.h"
#include "cryptopp/rsa.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/base64.h"

std::string encryptPrivateKey(CryptoPP::RSA::PrivateKey &privateKey, std::string &encryptionKey);
CryptoPP::RSA::PrivateKey decryptPrivateKey(std::string& encryptedData, std::string &encryptionKey);