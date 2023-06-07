#pragma once

#include <iostream>

#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/pwdbased.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"

#define cbyte unsigned char

bool verifyPassword(const std::string& password, const std::string& storedSalt, const std::string& storedHash);