#pragma once
#include <iostream>
#include <cstdlib>
#include <boost/asio.hpp>
#include "Protocol.h"

using boost::asio::ip::tcp;

class ResponseHeader {
public:
	char version;
	uint16_t code;
	uint32_t payload_size;

	ResponseHeader() : version(0), code(0), payload_size(0) { }
};

class Response {
public:
	ResponseHeader header;
	
protected:
	Response() { }
};

class RegistrationSuccess: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
};

class RegistrationFailure: public Response {

};

class PublicKeyRecieved: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	char EncryptedAESKey[Constants::Sizes_In_Bytes::AES_KEY];
};

class FileRecieved: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	uint32_t content_size;
	char file_name[Constants::Sizes_In_Bytes::FILE_NAME];
	uint32_t checksum;
};

class MessageRecieved: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
};

class AllowRelogin: public Response {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
	char EncryptedAESKey[Constants::Sizes_In_Bytes::AES_KEY];
};

class DeclineRelogin {
public:
	char client_id[Constants::Sizes_In_Bytes::CLIENT_ID];
};

class GeneralServerError {

};