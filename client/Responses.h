#pragma once
#include <iostream>
#include <cstdlib>
#include "Constants.h"

class ResponseHeader {
public:
	char version;
	uint16_t code;
	uint32_t payload_size;
};

class Response {
public:
	ResponseHeader header;
	
protected:
	Response() { }
};

class RegistrationSuccess: public Response {
public:
	char client_id[Constants::CLIENT_ID_LENGTH];
};

class RegistrationFailure: public Response {

};

class PublicKeyRecieved: public Response {
public:
	char client_id[Constants::CLIENT_ID_LENGTH];
	char EncryptedAESKey[Constants::NUM_OF_BYTES_IN_AES_KEY];
};


class FileRecieved: public Response {
public:
	char client_id[Constants::CLIENT_ID_LENGTH];
	uint32_t content_size;
	char file_name[Constants::FILE_NAME_LENGTH];
	uint32_t checksum;
};

class MessageRecieved: public Response {
public:
	char client_id[Constants::CLIENT_ID_LENGTH];
};

class AllowRelogin: public Response {
public:
	char client_id[Constants::CLIENT_ID_LENGTH];
	char EncryptedAESKey[Constants::NUM_OF_BYTES_IN_AES_KEY];
};

class DeclineRelogin {
public:
	char client_id[Constants::CLIENT_ID_LENGTH];
};

class GeneralServerError {

};