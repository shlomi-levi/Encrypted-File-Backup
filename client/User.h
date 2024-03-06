#pragma once
#include <iostream>
#include "AESWrapper.h"
#include "RSAWrapper.h"

using std::string;
using std::unique_ptr;

class User {
private:
	string get_file_name();

public:
	char name[Constants::CLIENT_NAME_LENGTH];
	char uuid[Constants::CLIENT_ID_LENGTH];
	char file_name[Constants::FILE_NAME_LENGTH];

	string file_path;
	string server_address;
	string server_port;

	unique_ptr<AESWrapper> aes_object;
	unique_ptr<RSAPrivateWrapper> rsa_object;

	User(string server_address, string server_port, string user_name, string file_path, string UUID="", string private_key="");

	void start();
};

