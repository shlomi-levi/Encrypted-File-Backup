#include <iostream>
#include <filesystem>
#include <fstream>
#include <boost/algorithm/hex.hpp>
#include <vector>
#include <sstream>
#include <exception>
#include "Utilities.h"
#include "Base64Wrapper.h"

using std::string;
using std::cout;
using std::endl;
using boost::algorithm::hex;

namespace Hex {
	string bytes_to_hex_string(const char* bytes, size_t length = Constants::Sizes_In_Bytes::CLIENT_ID) {
		std::string str;
		hex(bytes, bytes + length, std::back_inserter(str));
		return str;
	}

	std::vector<char> hex_string_to_bytes(const std::string& hex) {
		std::vector<char> bytes;

		for(unsigned int i = 0; i < hex.length(); i += 2) {
			std::string byteString = hex.substr(i, 2);
			bytes.push_back((char) strtol(byteString.c_str(), NULL, 16));
		}
		return bytes;
	}
}

namespace Endian {
	bool is_little_endian() {
		static int num = 1;
		return (*(char*) &num == 1) ? true : false;
	}

	template <typename intType>
	void flip_endianness(intType& src) {
		uint8_t buffer[sizeof(intType)] = {0};
		memcpy(buffer, &src, sizeof(intType));
		std::reverse(buffer, buffer + sizeof(intType));
		memcpy(&src, buffer, sizeof(intType));
	}
}

void copy_from_string_to_array(char array[], int len, const std::string& src, bool add_terminating_zero=false) {
	static int src_string_len;
	static int i;

	src_string_len = src.length();

	for(i = 0 ; i < len ; i++)
		array[i] = '\0'; // fill with zeros.

	if(!add_terminating_zero && src_string_len != len)
		throw std::invalid_argument("Src string length is bigger than len argument");

	else if(add_terminating_zero && src_string_len + 1 > len)
		throw std::invalid_argument("Not enough cells in array to add terminating zero");

	for(i = 0 ; i < src_string_len ; i++)
		array[i] = src[i];

	if(add_terminating_zero)
		array[i] = '\0';
}

void read_transfer_file(client_info& result) {
	if(!std::filesystem::exists(Constants::TRANSFER_FILE_PATH)) {
		throw std::logic_error(Constants::TRANSFER_FILE_PATH + "doesnt exist.");
		exit(1);
	}

	std::ifstream f;
	string server_details;

	try {
		std::string line;

		f.open(Constants::TRANSFER_FILE_PATH, std::ios::in);

		if(!f.is_open()) {
			throw std::logic_error("Couldn't open the file " + Constants::TRANSFER_FILE_PATH);
			exit(1);
		}

		string* variables[] = {&server_details, &result.client_name, &result.file_path};

		for(string* var : variables) {
			if(!std::getline(f, line)) {
				throw std::logic_error(Constants::TRANSFER_FILE_PATH + " is not according to format.");
				exit(1);
			}

			(*var) = line;
		}

		f.close();

		size_t colon_pos = server_details.find(':');

		if(colon_pos == string::npos) {
			throw std::logic_error(Constants::TRANSFER_FILE_PATH + " is not according to format.missing colon on server address part.");
			exit(1);
		}

		result.server_ip = server_details.substr(0, colon_pos);
		result.server_port = server_details.substr(colon_pos + 1);
	}

	catch(const std::exception& e) {
		if(f.is_open())
			f.close();

		cout << e.what();
		exit(1);
	}
}

void read_me_file(client_info& result) {
	std::ifstream f;

	try {
		std::string line;

		f.open(Constants::ME_FILE_PATH, std::ios::in);

		if(!f.is_open()) {
			cout << "The file " << Constants::ME_FILE_PATH << " exists, but the system could not open it." << endl;
			exit(1);
		}

		string* variables[] = {&result.client_name, &result.UUID, &result.private_key_base64};

		for(string* var : variables) {
			if(!std::getline(f, line)) {
				cout << Constants::ME_FILE_PATH << " is not according to format." << endl;
				exit(1);
			}

			(*var) = line;
		}

		f.close();
	}

	catch(const std::exception& e) {
		if(f.is_open())
			f.close();

		cout << e.what();
		exit(1);
	}
}

void read_priv_key_file(client_info& result) {
	std::ifstream f;

	try {
		f.open(Constants::PRIV_KEY_PATH, std::ios::in);

		if(!f.is_open()) {
			throw std::logic_error("The file " << Constants::PRIV_KEY_PATH << " exists, but the system could not open it.");
			exit(1);
		}


		if(!std::getline(f, result.private_key)) {
			throw std::logic_error(Constants::PRIV_KEY_PATH + " is not according to format.");
			exit(1);
		}

		f.close();
	}

	catch(const std::exception& e) {
		if(f.is_open())
			f.close();

		cout << e.what();
		exit(1);
	}
}

client_info get_client_info() {
	client_info result;
	
	result.UUID = "";
	result.private_key_base64 = "";
	result.private_key = "";
	
	read_transfer_file(result);

	if(!std::filesystem::exists(result.file_path)) {
		cout << "File to transfer (" << result.file_path << ") not found." << endl;
		exit(1);
	}

	if(!std::filesystem::exists(Constants::ME_FILE_PATH))
		return result;

	read_me_file(result);

	if(!std::filesystem::exists(Constants::PRIV_KEY_PATH)) {
		throw std::logic_error(Constants::ME_FILE_PATH + "exists, but " + Constants::PRIV_KEY_PATH + " doesnt exist.");
		exit(1);
	}

	read_priv_key_file(result);

	if(result.private_key != Base64Wrapper::decode(result.private_key_base64))
		throw std::logic_error("Private key in " + Constants::PRIV_KEY_PATH + " is different than the one in " + Constants::ME_FILE_PATH);
	
	return result;
}