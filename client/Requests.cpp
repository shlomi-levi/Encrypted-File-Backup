#include <iostream>
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

	return *this;
}

void RequestHeader::init(const char client_id[], uint16_t code, uint32_t payload_size) {
	std::copy(client_id, client_id + Constants::Sizes_In_Bytes::CLIENT_ID, this->client_id);
	this->version = Constants::CLIENT_VERSION;
	this->code = code;
	this->payload_size = payload_size;
}

std::vector<uint8_t> RequestHeader::pack() {
	std::vector<uint8_t> result {};

	for(int i = 0 ; i < Constants::Sizes_In_Bytes::CLIENT_ID ; i++)
		result.push_back(client_id[i]);

	uint16_t _code = code;
	uint32_t _payload_size = payload_size;

	if(!Endian::is_little_endian()) {
		Endian::flip_endianness(_code);
		Endian::flip_endianness(_payload_size);
	}

	result.push_back(version);

	for(int i = 1 ; i <= sizeof(_code) ; i++ )
		result.push_back(Hex::get_byte(_code, i));

	for(int i = 1 ; i <= sizeof(_payload_size) ; i++)
		result.push_back(Hex::get_byte(_payload_size, i));

	return result;
}

Registration::Registration(const User& u) {
	this->header.init(Constants::EMPTY_NAME, Constants::Requests::codes::Registration, Constants::Requests::payload_sizes::Registration);

	std::copy(u.name, u.name + Constants::Sizes_In_Bytes::CLIENT_NAME, this->client_name);
}

std::vector<uint8_t> Registration::pack() {
	std::vector<uint8_t> res = header.pack();
	
	for(int i = 0 ; i < Constants::Sizes_In_Bytes::CLIENT_NAME ; i++)
		res.push_back(client_name[i]);

	return res;
}

PublicKeyTransfer::PublicKeyTransfer(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::PublicKeyTransfer, Constants::Requests::payload_sizes::PublicKeyTransfer);

	std::copy(u.name, u.name + Constants::Sizes_In_Bytes::CLIENT_NAME, this->client_name);

	string pub_key = u.rsa_object->getPublicKey();

	copy_from_string_to_array(this->public_key, Constants::Sizes_In_Bytes::PUBLIC_KEY, pub_key);
}

std::vector<uint8_t> PublicKeyTransfer::pack() {
	std::vector<uint8_t> res = header.pack();

	for(int i = 0; i < Constants::Sizes_In_Bytes::CLIENT_NAME ; i++)
		res.push_back(client_name[i]);


	for(int i = 0 ; i < Constants::Sizes_In_Bytes::PUBLIC_KEY ; i++)
		res.push_back(public_key[i]);

	return res;
}

Relogin::Relogin(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::Relogin, Constants::Requests::payload_sizes::Relogin);
	std::copy(u.name, u.name + Constants::Sizes_In_Bytes::CLIENT_NAME, this->client_name);
}

std::vector<uint8_t> Relogin::pack() {
	std::vector<uint8_t> res = header.pack();

	for(int i = 0; i < Constants::Sizes_In_Bytes::CLIENT_NAME; i++)
		res.push_back(client_name[i]);

	return res;
}

FileTransfer::FileTransfer(const User& u, uint32_t content_size, uint32_t original_file_size, uint16_t packet_number, uint16_t total_packets) {

	this->header.init(u.uuid, Constants::Requests::codes::FileTransfer, Constants::Requests::payload_sizes::FileTransfer);
	this->content_size = content_size;
	this->original_file_size = original_file_size;
	this->packet_number = packet_number;
	this->total_packets = total_packets;

	std::copy(u.file_name, u.file_name + Constants::Sizes_In_Bytes::FILE_NAME, this->file_name);
}

std::vector<uint8_t> FileTransfer::pack() {
	std::vector<uint8_t> res = header.pack();

	uint32_t _content_size = content_size;
	uint32_t _original_file_size = original_file_size;
	uint16_t _packet_number = packet_number;
	uint16_t _total_packets = total_packets;

	if(!Endian::is_little_endian()) {
		Endian::flip_endianness(_content_size);
		Endian::flip_endianness(_original_file_size);
		Endian::flip_endianness(_packet_number);
		Endian::flip_endianness(_total_packets);
	}

	for(int i = 1 ; i <= sizeof(_content_size) ; i++)
		res.push_back(Hex::get_byte(_content_size, i));

	for(int i = 1; i <= sizeof(_original_file_size); i++)
		res.push_back(Hex::get_byte(_original_file_size, i));

	for(int i = 1; i <= sizeof(_packet_number); i++)
		res.push_back(Hex::get_byte(_packet_number, i));

	for(int i = 1; i <= sizeof(_total_packets); i++)
		res.push_back(Hex::get_byte(_total_packets, i));

	for(int i = 0 ; i < Constants::Sizes_In_Bytes::FILE_NAME ; i++)
		res.push_back(file_name[i]);

	// we send the content after.

	return res;
}

ValidCRC::ValidCRC(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::ValidCRC, Constants::Requests::payload_sizes::ValidCRC);
	std::copy(u.file_name, u.file_name + Constants::Sizes_In_Bytes::FILE_NAME, this->file_name);
}

std::vector<uint8_t> ValidCRC::pack() {
	std::vector<uint8_t> res = header.pack();
	for(int i = 0; i < Constants::Sizes_In_Bytes::FILE_NAME; i++)
		res.push_back(file_name[i]);

	return res;
}

InvalidCRC::InvalidCRC(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::InvalidCRC, Constants::Requests::payload_sizes::InvalidCRC);
	std::copy(u.file_name, u.file_name + Constants::Sizes_In_Bytes::FILE_NAME, this->file_name);
}

std::vector<uint8_t> InvalidCRC::pack() {
	std::vector<uint8_t> res = header.pack();
	for(int i = 0; i < Constants::Sizes_In_Bytes::FILE_NAME; i++)
		res.push_back(file_name[i]);

	return res;
}

InvalidCRCFourthTime::InvalidCRCFourthTime(const User& u) {
	this->header.init(u.uuid, Constants::Requests::codes::InvalidCRCFourthTime, Constants::Requests::payload_sizes::InvalidCRCFourthTime);
	std::copy(u.file_name, u.file_name + Constants::Sizes_In_Bytes::FILE_NAME, this->file_name);
}

std::vector<uint8_t> InvalidCRCFourthTime::pack() {
	std::vector<uint8_t> res = header.pack();
	for(int i = 0; i < Constants::Sizes_In_Bytes::FILE_NAME; i++)
		res.push_back(file_name[i]);

	return res;
}