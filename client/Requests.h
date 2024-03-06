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
	char client_id[Constants::CLIENT_ID_LENGTH];
	uint8_t version;
	uint16_t code;
	uint32_t payload_size;

	void init(const char client_id[], uint16_t code, uint32_t payload_size);
};

class Request {
public:
	RequestHeader header;

	virtual string pack() = 0;

	// virtual static Request create_request_from_payload(RequestHeader, )

protected:
	Request() {}
};

class Registration: public Request {
public:
	Registration(const User& u);
	char client_name[Constants::CLIENT_NAME_LENGTH];

};

class PublicKeyTransfer: public Request {
public:
	PublicKeyTransfer(const User& u);
	char client_name[Constants::CLIENT_NAME_LENGTH];
	char public_key[Constants::PUBLIC_KEY_LENGTH_IN_BYTES];
};

class Relogin: public Request {
public:
	Relogin(const User& u);
	char client_name[Constants::CLIENT_NAME_LENGTH];
};

class FileTransfer: public Request {
public:
	FileTransfer(const User& u, uint32_t content_size, uint32_t original_file_size, uint16_t packet_number, uint16_t total_packets, const std::string& message_content);

	uint32_t content_size;
	uint32_t original_file_size;
	uint16_t packet_number;
	uint16_t total_packets;
	char file_name[Constants::FILE_NAME_LENGTH];
	char message_content[Constants::BUFFER_SIZE_FILE_TRANSFER];
};

class ValidCRC: public Request {
public:
	ValidCRC(const User& u);
	char file_name[Constants::FILE_NAME_LENGTH];
};

class InvalidCRC: public Request {
public:
	InvalidCRC(const User& u);
	char file_name[Constants::FILE_NAME_LENGTH];
};

class InvalidCRCFourthTime: public Request {
public:
	InvalidCRCFourthTime(const User& u);
	char file_name[Constants::FILE_NAME_LENGTH];
};
		