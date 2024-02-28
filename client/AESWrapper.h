#pragma once

#include <string>
#include "Constants.h"


class AESWrapper
{
public:
	static const unsigned int DEFAULT_KEYLENGTH = Constants::NUM_OF_BITS_IN_AES_KEY / 8;
private:
	unsigned char _key[DEFAULT_KEYLENGTH];
	AESWrapper(const AESWrapper& aes);
public:
	static unsigned char* GenerateKey(unsigned char* buffer, unsigned int length);

	AESWrapper();
	AESWrapper(const unsigned char* key, unsigned int size);
	~AESWrapper();

	const unsigned char* getKey() const;

	std::string encrypt(const char* plain, unsigned int length);
	std::string decrypt(const char* cipher, unsigned int length);
};