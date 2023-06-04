#include <iostream>

#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/filters.h"
#include "cryptopp/files.h"

void EncryptStream(const std::string &inputFile, const std::string &outputFile, const std::string &key);
void DecryptStream(const std::string &inputFile, const std::string &outputFile, const std::string &key);