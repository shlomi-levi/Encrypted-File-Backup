#pragma once
#include <iostream>
#include "AESWrapper.h"
#include "RSAWrapper.h"

using std::string;

class User {
public:
	string name;
	string UUID;
	AESWrapper AESObject;
	RSAPrivateWrapper RSAObject;
};