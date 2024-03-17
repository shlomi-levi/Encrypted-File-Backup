#pragma once
#ifndef _RESPONSES_GUARD
#define _RESPONSES_GUARD
#include <boost/asio.hpp>
#include "Protocol.h"

class User;
using boost::asio::ip::tcp;

class ResponseHeader {
public:
	char version;
	uint16_t code;
	uint32_t payload_size;

	ResponseHeader() : version(0), code(0), payload_size(0) { }
	void unpack(const std::vector<uint8_t>& raw_data);

	ResponseHeader& operator=(const ResponseHeader& other);
};


class Response {
public:
	ResponseHeader header;
	
public:
	Response() { }
	static std::unique_ptr<Response> get_response(tcp::socket& s, User* u=nullptr);
	virtual ~Response() { }
	virtual void unpack_payload(const std::vector<uint8_t>& bytes) = 0;
};

class RegistrationSuccess: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	void unpack_payload(const std::vector<uint8_t>& bytes);
};

class RegistrationFailure: public Response {
	void unpack_payload(const std::vector<uint8_t>& bytes) { }
};

class PublicKeyRecieved: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	string encrypted_aes_key;

	void unpack_payload(const std::vector<uint8_t>& bytes);
	
};

class FileRecieved: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	uint32_t content_size;
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];
	uint32_t checksum;

	void unpack_payload(const std::vector<uint8_t>& bytes);
};

class MessageRecieved: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	void unpack_payload(const std::vector<uint8_t>& bytes);
};

class AllowRelogin: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	string encrypted_aes_key;

	void unpack_payload(const std::vector<uint8_t>& bytes);
};

class DeclineRelogin: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	void unpack_payload(const std::vector<uint8_t>& bytes);
};

class GeneralServerError: public Response {
public:
	void unpack_payload(const std::vector<uint8_t>& bytes) { }
};
#endif