#pragma once
#ifndef _UTILITIES_GUARD
#define _UTILITIES_GUARD

#include <vector>
#include <string>
#include <iostream>
#include "Protocol.h"

using std::string;

class User;

void create_client_files(const User& u);

namespace Hex {
	string bytes_to_hex_string(const char* bytes, size_t length = Constants::Sizes_In_Bytes::CLIENT_ID);
	
	std::vector<char> hex_string_to_bytes(const std::string& hex); 

	template <typename intType>
	uint8_t get_byte(const intType& src, const int byte_number) {
		if(byte_number > sizeof(src))
			throw std::logic_error("Src variable doesn't contain that many bytes.");

		uint8_t mask = 0xFF;

		return (uint8_t) (src >> ((sizeof(src) - byte_number) * 8)) & mask;
	}

	template <typename intType>
	void copy_bytes(intType& src, const std::vector<uint8_t> bytes) {
		src = 0;

		if(sizeof(src) != bytes.size())
			throw std::logic_error("Number of bytes in src variable differs from 'bytes' vector length.");

		for(int i = 0 ; i < sizeof(src) ; i++) {
			size_t offset = sizeof(src) - (i + 1);

			src |= ( (uint64_t) (bytes[i]) ) << (offset * 8);
		}
	}
}

namespace Endian {
	bool is_little_endian();

	template <typename intType>
	void flip_endianness(intType& src) {
		uint8_t buffer[sizeof(intType)] = {0};
		memcpy(buffer, &src, sizeof(intType));
		std::reverse(buffer, buffer + sizeof(intType));
		memcpy(&src, buffer, sizeof(intType));
	}
}

void copy_from_string_to_array(char array[], int len, const std::string& src, bool add_terminating_zero = false);

struct client_info {
	string server_ip;
	string server_port;
	string client_name;
	string file_path;
	string UUID;
	string private_key_base64;
	string private_key_priv_key_file;
	string decoded_private_key;
};

client_info get_client_info();

#endif