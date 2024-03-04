#include <algorithm>
#include <string.h>
#include "Requests.h"
#include "Utilities.h"

RequestHeader::RequestHeader(const string& client_id, uint8_t version, uint16_t code, uint32_t payload_size) {
	copy_from_string_to_array(this->client_id, Constants::CLIENT_ID_LENGTH, client_id);
	this->version = version;
	this->code = code;
	this->payload_size = payload_size;
}

Registration::Registration(const string& client_name) {
	copy_from_string_to_array(this->client_name, Constants::CLIENT_NAME_LENGTH, client_name, true);
}

PublicKeyTransfer::PublicKeyTransfer(const string& client_name, char public_key[]) {
	copy_from_string_to_array(this->client_name, Constants::CLIENT_NAME_LENGTH, client_name, true);

	strcpy_s(this->public_key, Constants::PUBLIC_KEY_LENGTH_IN_BYTES, public_key);
}

Relogin::Relogin(const string& client_name) {
	copy_from_string_to_array(this->client_name, Constants::CLIENT_NAME_LENGTH, client_name, true);
}

FileTransfer::FileTransfer(uint32_t content_size, uint32_t original_file_size, uint16_t packet_number, uint16_t total_packets, const std::string& file_name, const std::string& message_content) {
	this->content_size = content_size;
	this->original_file_size = original_file_size;
	this->packet_number = packet_number;
	this->total_packets = total_packets;
	
	copy_from_string_to_array(this->file_name, Constants::FILE_NAME_LENGTH, file_name, true);
	copy_from_string_to_array(this->message_content, Constants::BUFFER_SIZE_FILE_TRANSFER, message_content, true);
}

ValidCRC::ValidCRC(const string& file_name) {
	copy_from_string_to_array(this->file_name, Constants::FILE_NAME_LENGTH, file_name, true);
}

InvalidCRC::InvalidCRC(const string& file_name) {
	copy_from_string_to_array(this->file_name, Constants::FILE_NAME_LENGTH, file_name, true);
}

InvalidCRCFourthTime::InvalidCRCFourthTime(const string& file_name) {
	copy_from_string_to_array(this->file_name, Constants::FILE_NAME_LENGTH, file_name, true);
}



