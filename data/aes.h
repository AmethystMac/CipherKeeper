#pragma once

#include <iostream>

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"
#include "cryptopp/base64.h"

std::string encryptStream(std::string &plainStream, std::string &key);
std::string decryptStream(std::string &encryptedStream, std::string &key);