#pragma once
#ifndef UTILITIES
#define UTILITIES

#include <vector>
#include "Constants.h"

using std::string;

namespace Hex {
	string bytes_to_hex_string(const char* bytes, size_t length = Constants::CLIENT_ID_LENGTH);
	
	std::vector<char> hex_string_to_bytes(const std::string& hex); 
}

struct client_info {
	string server_ip;
	string server_port;
	string client_name;
	string file_path;
	string UUID;
	string private_key;
};

client_info get_client_info();

#endif