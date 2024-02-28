#pragma once
#include <iostream>
#include "AESWrapper.h"
#include "RSAWrapper.h"

using std::string;

class User {
public:
	char name[Constants::CLIENT_NAME_LENGTH];
	char UUID[Constants::CLIENT_ID_LENGTH];
	AESWrapper AESObject;
	RSAPrivateWrapper RSAObject;

	User(string server_address, string server_port, string user_name, string file_path, string UUID="", string private_key="");

	void start();
};

