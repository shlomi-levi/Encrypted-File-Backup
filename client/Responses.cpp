#include <iostream>

#include "Responses.h"
#include "Utilities.h"
#include "User.h"

ResponseHeader& ResponseHeader::operator=(const ResponseHeader& other) {
	if(this == &other)
		return *this;

	version = other.version;
	code = other.code;
	payload_size = other.payload_size;

	return *this;
}

void ResponseHeader::unpack(const std::vector<uint8_t>& raw_data) {
	std::vector<uint8_t> _version(Constants::Responses::RESPONSE_VERSION_SIZE);
	std::vector<uint8_t> _code (Constants::Responses::RESPONSE_CODE_SIZE);
	std::vector<uint8_t> _payload_size(Constants::Responses::RESPONSE_PAYLOAD_SIZE);

	size_t offset = 0;
	
	// flip order of bytes since we recieve the bytes in small endian.

	for(int i = 0, j = _version.size() + offset - 1 ; i < _version.size() ; i++, j--) {
		_version[i] = raw_data[j];
		offset++;
	}

	for(int i = 0, j = _code.size() + offset - 1 ; i < _code.size() ; i++, j--) {
		_code[i] = raw_data[j];
		offset ++;
	}

	for(int i = 0, j = _payload_size.size() + offset - 1; i < _payload_size.size() ; i++, j--) {
		_payload_size[i] = raw_data[j];
		offset ++;
	}

	Hex::copy_bytes(version, _version);
	Hex::copy_bytes(code, _code);
	Hex::copy_bytes(payload_size, _payload_size);
}

void RegistrationSuccess::unpack_payload(const std::vector<uint8_t>& bytes) {
	if(Constants::Sizes_In_Bytes::CLIENT_ID != bytes.size())
		throw std::logic_error("Invalid payload size.");
	
	for(int i = 0 ; i < Constants::Sizes_In_Bytes::CLIENT_ID ; i++)
		client_id[i] = bytes[i];
}

void PublicKeyRecieved::unpack_payload(const std::vector<uint8_t>& bytes) {
	for(int i = 0; i < Constants::Sizes_In_Bytes::CLIENT_ID; i++)
		client_id[i] = bytes[i];
	

	for(int i = Constants::Sizes_In_Bytes::CLIENT_ID ; i < bytes.size() ; i++)
		encrypted_aes_key += bytes[i];
}

void FileRecieved::unpack_payload(const std::vector<uint8_t>& bytes) {
	for(int i = 0; i < Constants::Sizes_In_Bytes::CLIENT_ID; i++)
		client_id[i] = bytes[i];

	size_t offset = Constants::Sizes_In_Bytes::CLIENT_ID;

	std::vector<uint8_t> _content_size (Constants::Sizes_In_Bytes::FILE_CONTENT_SIZE);
	std::vector<uint8_t> _checksum (Constants::Sizes_In_Bytes::CHECKSUM);

	for(int i = 0, j = _content_size.size() + offset - 1; i < _content_size.size(); i++, j--) {
		_content_size[i] = bytes[j];
		offset++;
	}

	for(int i = 0 ; i < Constants::Sizes_In_Bytes::FILE_NAME ; i++)
		file_name[i] = bytes[i + offset];

	offset += Constants::Sizes_In_Bytes::FILE_NAME;

	for(int i = 0, j = _checksum.size() + offset - 1; i < _checksum.size(); i++, j--) {
		_checksum[i] = bytes[j];
		offset++;
	}

	Hex::copy_bytes(content_size, _content_size);
	Hex::copy_bytes(checksum, _checksum);
}

void MessageRecieved::unpack_payload(const std::vector<uint8_t>& bytes) {
	for(int i = 0; i < Constants::Sizes_In_Bytes::CLIENT_ID; i++)
		client_id[i] = bytes[i];
}

void AllowRelogin::unpack_payload(const std::vector<uint8_t>& bytes) {
	for(int i = 0; i < Constants::Sizes_In_Bytes::CLIENT_ID; i++)
		client_id[i] = bytes[i];

	for(int i = Constants::Sizes_In_Bytes::CLIENT_ID ; i < bytes.size() ; i++)
		encrypted_aes_key += bytes[i];
}

void DeclineRelogin::unpack_payload(const std::vector<uint8_t>& bytes) {
	for(int i = 0; i < Constants::Sizes_In_Bytes::CLIENT_ID; i++)
		client_id[i] = bytes[i];
}

std::unique_ptr<Response> Response::get_response(tcp::socket& s, User* u) {
	ResponseHeader header;
	std::vector<uint8_t> header_bytes (Constants::Responses::HEADER_SIZE);
	
	boost::asio::read(s, boost::asio::buffer(header_bytes));
	header.unpack(header_bytes);

	std::unique_ptr<Response> res;

	switch(header.code) {
		case Constants::Responses::codes::RegistrationSuccess:
			res = std::make_unique<RegistrationSuccess>();
			break;

		case Constants::Responses::codes::RegistrationFailure:
			res = std::make_unique<RegistrationFailure>();
			break;

		case Constants::Responses::codes::PublicKeyRecieved:
			res = std::make_unique<PublicKeyRecieved>();
			break;

		case Constants::Responses::codes::FileRecieved:
			res = std::make_unique<FileRecieved>();
			break;

		case Constants::Responses::codes::MessageRecieved:
			res = std::make_unique<MessageRecieved>();
			break;

		case Constants::Responses::codes::AllowRelogin:
			res = std::make_unique<AllowRelogin>();
			break;

		case Constants::Responses::codes::DeclineRelogin:
			res = std::make_unique<DeclineRelogin>();
			break;

		case Constants::Responses::codes::GeneralServerError:
			res = std::make_unique<GeneralServerError>();
			break;

		default:
			std::cerr << "Invalid response code recieved from server. Exiting" << std::endl;
			s.close();
			exit(1);
	}

	res->header = header;

	std::vector<uint8_t> payload_bytes (res->header.payload_size);
	boost::asio::read(s, boost::asio::buffer(payload_bytes));

	res->unpack_payload(payload_bytes);

	return res;
}