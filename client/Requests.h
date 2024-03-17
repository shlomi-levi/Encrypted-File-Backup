#pragma once
#ifndef _REQUESTS_GUARD
#define _REQUESTS_GUARD
#include <cstdint>
#include <vector>
#include "Protocol.h"

using std::string;
using std::vector;

class User;

class RequestHeader {
public:
	RequestHeader() : version(0), code(0), payload_size(0) {
		for(int i = 0 ; i < Constants::Sizes_In_Bytes::CLIENT_ID ; i++)
			client_id[i] = 0;
	}

	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	uint8_t version;
	uint16_t code;
	uint32_t payload_size;

	void init(const char client_id[], uint16_t code, uint32_t payload_size);

	std::vector<uint8_t> pack();

	RequestHeader& operator=(const RequestHeader& other);
};

class Request {
public:
	virtual std::vector<uint8_t> pack() = 0;
	RequestHeader header;
	Request() {}
};

class Registration: public Request {
public:
	Registration(const User& u);
	char client_name[Constants::Sizes_In_Bytes::CLIENT_NAME];
	std::vector<uint8_t> pack();

};

class PublicKeyTransfer: public Request {
public:
	PublicKeyTransfer(const User& u);
	char client_name[Constants::Sizes_In_Bytes::CLIENT_NAME];
	char public_key[Constants::Sizes_In_Bytes::PUBLIC_KEY];
	std::vector<uint8_t> pack();
};

class Relogin: public Request {
public:
	Relogin(const User& u);
	char client_name[Constants::Sizes_In_Bytes::CLIENT_NAME];
	std::vector<uint8_t> pack();
};

class FileTransfer: public Request {
public:
	FileTransfer(const User&, uint32_t, uint16_t, uint16_t, const string&);

	uint32_t content_size;
	uint32_t original_file_size;
	uint16_t packet_number;
	uint16_t total_packets;
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];
	string content;
	std::vector<uint8_t> pack();
};

class ValidCRC: public Request {
public:
	ValidCRC(const User& u);
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];
	std::vector<uint8_t> pack();
};

class InvalidCRC: public Request {
public:
	InvalidCRC(const User& u);
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];
	std::vector<uint8_t> pack();
};

class InvalidCRCFourthTime: public Request {
public:
	InvalidCRCFourthTime(const User& u);
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];
	std::vector<uint8_t> pack();
};
#endif		