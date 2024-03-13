#pragma once
#ifndef _AESWRAPPER_GUARD
#define _AESWRAPPER_GUARD

#include <string>
#include "Protocol.h"


class AESWrapper
{
public:
	static const unsigned int DEFAULT_KEYLENGTH = Constants::Sizes_In_Bits::AES_KEY / 8; // byte is always 8 bits.

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
#endif