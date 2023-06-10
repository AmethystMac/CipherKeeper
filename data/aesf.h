// Header file for AES-256 to encrypt file
#pragma once

#include <iostream>

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"

void encryptFile(std::string& inputFile, std::string& key);
void decryptFile(std::string& inputFile, std::string& key);