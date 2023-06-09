// Header for AES-256 to encrypt a file
#pragma once

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"

void encryptFile(std::string &inFileLocation, std::string &outFileLocation, std::string &key);
void decryptFile(std::string &inFileLocation, std::string &outFileLocation, std::string &key);