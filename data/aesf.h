#include <iostream>

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"

void EncryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& key);
void DecryptFile(const std::string& inputFile, const std::string& outputFile, const std::string& key);