#pragma once
#include <iostream>
#include <cstdint>
#include <vector>
#include "Protocol.h"

using std::string;
using std::vector;

class RequestHeader {
public:
	RequestHeader() {}
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	uint8_t version;
	uint16_t code;
	uint32_t payload_size;

	void init(const char client_id[], uint16_t code, uint32_t payload_size);

	RequestHeader& operator=(const RequestHeader& other);
};

class Request {
public:
	RequestHeader header;

protected:
	Request() {}
};

class Registration: public Request {
public:
	Registration(const User& u);
	char client_name[Constants::Sizes_In_Bytes::CLIENT_NAME];

};

class PublicKeyTransfer: public Request {
public:
	PublicKeyTransfer(const User& u);
	char client_name[Constants::Sizes_In_Bytes::CLIENT_NAME];
	char public_key[Constants::Sizes_In_Bytes::PUBLIC_KEY];
};

class Relogin: public Request {
public:
	Relogin(const User& u);
	char client_name[Constants::Sizes_In_Bytes::CLIENT_NAME];
};

class FileTransfer: public Request {
public:
	FileTransfer(const User& u, uint32_t content_size, uint32_t original_file_size, uint16_t packet_number, uint16_t total_packets);

	uint32_t content_size;
	uint32_t original_file_size;
	uint16_t packet_number;
	uint16_t total_packets;
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];
};

class ValidCRC: public Request {
public:
	ValidCRC(const User& u);
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];
};

class InvalidCRC: public Request {
public:
	InvalidCRC(const User& u);
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];
};

class InvalidCRCFourthTime: public Request {
public:
	InvalidCRCFourthTime(const User& u);
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];
};
		