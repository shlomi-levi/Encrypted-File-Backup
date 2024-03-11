#pragma once
#ifndef UTILITIES
#define UTILITIES

#include <vector>
#include "Protocol.h"

using std::string;

namespace Hex {
	string bytes_to_hex_string(const char* bytes, size_t length = Constants::Sizes_In_Bytes::CLIENT_ID);
	
	std::vector<char> hex_string_to_bytes(const std::string& hex); 
}

namespace Endian {
	bool is_little_endian();

	template <typename intType>
	void flip_endianness(intType& src);
}

void copy_from_string_to_array(char array[], int len, const std::string& src, bool add_terminating_zero = false);

struct client_info {
	string server_ip;
	string server_port;
	string client_name;
	string file_path;
	string UUID;
	string private_key_base64;
	string private_key;
};

client_info get_client_info();

#endif