#pragma once
#ifndef UTILITIES
#define UTILITIES

#include <vector>
#include "Protocol.h"

using std::string;

namespace Hex {
	string bytes_to_hex_string(const char* bytes, size_t length = Constants::CLIENT_ID_LENGTH);
	
	std::vector<char> hex_string_to_bytes(const std::string& hex); 
}

void copy_from_string_to_array(char array[], int len, const std::string& src, bool add_terminating_zero = false);

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