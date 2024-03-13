#pragma once
#ifndef _BASE64WRAPPER_GUARD
#define _BASE64WRAPPER_GUARD
#include <string>
#include <base64.h>


class Base64Wrapper
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};
#endif