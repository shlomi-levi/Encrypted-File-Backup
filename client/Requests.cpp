#include <algorithm>
#include <string.h>
#include "Requests.h"
#include "Utilities.h"
#include "User.h"

void RequestHeader::init(const char client_id[], uint16_t code, uint32_t payload_size) {
	std::copy(client_id, client_id + Constants::CLIENT_ID_LENGTH, this->client_id);
	this->version = Constants::CLIENT_VERSION;
	this->code = code;
	this->payload_size = payload_size;
}

Registration::Registration(const User& u) {
	this->header.init(Constants::EMPTY_STRING, Constants::Requests::codes::Registration, Constants::Requests::payload_sizes::Registration);

	std::copy(u.name, u.name + Constants::CLIENT_NAME_LENGTH, this->client_name);
}

PublicKeyTransfer::PublicKeyTransfer(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::PublicKeyTransfer, Constants::Requests::payload_sizes::PublicKeyTransfer);

	std::copy(u.name, u.name + Constants::CLIENT_NAME_LENGTH, this->client_name);

	string pub_key = u.rsa_object->getPublicKey();

	copy_from_string_to_array(this->public_key, Constants::PUBLIC_KEY_LENGTH_IN_BYTES, pub_key);
}

Relogin::Relogin(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::Relogin, Constants::Requests::payload_sizes::Relogin);
	std::copy(u.name, u.name + Constants::CLIENT_NAME_LENGTH, this->client_name);
}

FileTransfer::FileTransfer(const User& u, uint32_t content_size, uint32_t original_file_size, uint16_t packet_number, uint16_t total_packets, const std::string& message_content) {
	this->header.init(u.uuid, Constants::Requests::codes::FileTransfer, Constants::Requests::payload_sizes::FileTransfer);
	this->content_size = content_size;
	this->original_file_size = original_file_size;
	this->packet_number = packet_number;
	this->total_packets = total_packets;

	std::copy(this->file_name, this->file_name + Constants::FILE_NAME_LENGTH, u.file_name);
	copy_from_string_to_array(this->message_content, Constants::BUFFER_SIZE_FILE_TRANSFER, message_content, true);
}

ValidCRC::ValidCRC(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::ValidCRC, Constants::Requests::payload_sizes::ValidCRC);
	std::copy(this->file_name, this->file_name + Constants::FILE_NAME_LENGTH, u.file_name);
}

InvalidCRC::InvalidCRC(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::InvalidCRC, Constants::Requests::payload_sizes::InvalidCRC);
	std::copy(this->file_name, this->file_name + Constants::FILE_NAME_LENGTH, u.file_name);
}

InvalidCRCFourthTime::InvalidCRCFourthTime(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::InvalidCRCFourthTime, Constants::Requests::payload_sizes::InvalidCRCFourthTime);
	std::copy(this->file_name, this->file_name + Constants::FILE_NAME_LENGTH, u.file_name);
}