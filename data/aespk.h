#pragma once

#include <iostream>

#include "cryptopp/aes.h"
#include "cryptopp/rsa.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/base64.h"

std::string encryptPrivateKey(const CryptoPP::RSA::PrivateKey& privateKey, const std::string& encryptionKey);
CryptoPP::RSA::PrivateKey decryptPrivateKey(const std::string& encryptedData, const std::string& encryptionKey);