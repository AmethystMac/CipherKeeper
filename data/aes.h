#include <iostream>

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"

std::string encryptStream(const std::string &plainStream, const std::string &key);
std::string decryptStream(const std::string &encryptedStream, const std::string &key);