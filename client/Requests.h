#pragma once
#include <iostream>
#include <cstdint>
#include "constants.h"

using std::string;

class RequestHeader {
public:
	char client_id[CLIENT_ID_LENGTH];
	uint8_t version;
	uint16_t code;
	uint32_t payload_size;
};

class Request {
protected:
	Request() { }

public:
	RequestHeader header;

	// virtual static Request create_request_from_payload(RequestHeader, )
};
		