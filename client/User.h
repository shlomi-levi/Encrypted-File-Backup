#pragma once
#ifndef _USER_GUARD
#define _USER_GUARD
#include <boost/asio.hpp>
#include "AESWrapper.h"
#include "RSAWrapper.h"

using std::string;
using std::unique_ptr;
using boost::asio::ip::tcp;

class User {

private:
	void get_file_name();
	void handle_relogin(tcp::socket& s);
	void handle_registration(tcp::socket& s);
	void handle_public_key_transfer(tcp::socket& s);
	void handle_file_transfer(tcp::socket& s);

public:
	bool has_uuid;

	char name[Constants::Sizes_In_Bytes::CLIENT_NAME];
	char uuid[Constants::Sizes_In_Bytes::CLIENT_ID];
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];

	string file_path;
	string server_address;
	string server_port;

	unique_ptr<AESWrapper> aes_object;
	unique_ptr<RSAPrivateWrapper> rsa_object;

	User(string server_address, string server_port, string user_name, string file_path, string UUID="", string private_key="");

	void start();
};
#endif