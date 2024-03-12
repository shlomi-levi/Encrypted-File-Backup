#include <algorithm>
#include <string.h>
#include "Requests.h"
#include "Utilities.h"
#include "User.h"

RequestHeader& RequestHeader::operator=(const RequestHeader& other) {
	if(this == &other)
		return *this;

	std::copy(other.client_id, other.client_id + Constants::Sizes_In_Bytes::CLIENT_ID, client_id);
	version = other.version;
	code = other.code;
	payload_size = other.payload_size;
}

void RequestHeader::init(const char client_id[], uint16_t code, uint32_t payload_size) {
	std::copy(client_id, client_id + Constants::Sizes_In_Bytes::CLIENT_ID, this->client_id);
	this->version = Constants::CLIENT_VERSION;
	this->code = code;
	this->payload_size = payload_size;

	if(!Endian::is_little_endian()) {
		Endian::flip_endianness(this->code);
		Endian::flip_endianness(this->payload_size);
	}
}

Registration::Registration(const User& u) {
	this->header.init(Constants::EMPTY_NAME, Constants::Requests::codes::Registration, Constants::Requests::payload_sizes::Registration);

	std::copy(u.name, u.name + Constants::Sizes_In_Bytes::CLIENT_NAME, this->client_name);
}

PublicKeyTransfer::PublicKeyTransfer(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::PublicKeyTransfer, Constants::Requests::payload_sizes::PublicKeyTransfer);

	std::copy(u.name, u.name + Constants::Sizes_In_Bytes::CLIENT_NAME, this->client_name);

	string pub_key = u.rsa_object->getPublicKey();

	copy_from_string_to_array(this->public_key, Constants::Sizes_In_Bytes::PUBLIC_KEY, pub_key);
}

Relogin::Relogin(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::Relogin, Constants::Requests::payload_sizes::Relogin);
	std::copy(u.name, u.name + Constants::Sizes_In_Bytes::CLIENT_NAME, this->client_name);
}

FileTransfer::FileTransfer(const User& u, uint32_t content_size, uint32_t original_file_size, uint16_t packet_number, uint16_t total_packets) {

	this->header.init(u.uuid, Constants::Requests::codes::FileTransfer, Constants::Requests::payload_sizes::FileTransfer);
	this->content_size = content_size;
	this->original_file_size = original_file_size;
	this->packet_number = packet_number;
	this->total_packets = total_packets;

	std::copy(this->file_name, this->file_name + Constants::Sizes_In_Bytes::FILE_NAME, u.file_name);

	if(!Endian::is_little_endian()) {
		Endian::flip_endianness(this->content_size);
		Endian::flip_endianness(this->original_file_size);
		Endian::flip_endianness(this->packet_number);
		Endian::flip_endianness(this->total_packets);
	}
}

ValidCRC::ValidCRC(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::ValidCRC, Constants::Requests::payload_sizes::ValidCRC);
	std::copy(this->file_name, this->file_name + Constants::Sizes_In_Bytes::FILE_NAME, u.file_name);
}

InvalidCRC::InvalidCRC(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::InvalidCRC, Constants::Requests::payload_sizes::InvalidCRC);
	std::copy(this->file_name, this->file_name + Constants::Sizes_In_Bytes::FILE_NAME, u.file_name);
}

InvalidCRCFourthTime::InvalidCRCFourthTime(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::InvalidCRCFourthTime, Constants::Requests::payload_sizes::InvalidCRCFourthTime);
	std::copy(this->file_name, this->file_name + Constants::Sizes_In_Bytes::FILE_NAME, u.file_name);
}