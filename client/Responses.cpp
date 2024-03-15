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

std::unique_ptr<Response> Response::get_response(tcp::socket& s, User* u) {
	ResponseHeader header;
	std::vector<uint8_t> header_bytes (Constants::Responses::HEADER_SIZE);
	boost::asio::read(s, boost::asio::buffer(header_bytes));
	header.unpack(header_bytes);

	static const std::unordered_map<int, int> sizeofTable = {
		{Constants::Responses::codes::RegistrationSuccess, sizeof(RegistrationSuccess)},
		{Constants::Responses::codes::RegistrationFailure, sizeof(RegistrationFailure)},
		{Constants::Responses::codes::PublicKeyRecieved, sizeof(PublicKeyRecieved)},
		{Constants::Responses::codes::FileRecieved, sizeof(FileRecieved)},
		{Constants::Responses::codes::MessageRecieved, sizeof(MessageRecieved)},
		{Constants::Responses::codes::AllowRelogin, sizeof(AllowRelogin)},
		{Constants::Responses::codes::DeclineRelogin, sizeof(DeclineRelogin)},
		{Constants::Responses::codes::GeneralServerError, sizeof(GeneralServerError)},
	};

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
			std::cout << "ERROR";
			// Todo: throw error, and remove previous line.
	}

	res->header = header;

	std::vector<uint8_t> payload_bytes (res->header.payload_size);
	boost::asio::read(s, boost::asio::buffer(payload_bytes));

	res.unpack_payload(payload_bytes);

	if(header.code == Constants::Responses::codes::PublicKeyRecieved) {
		PublicKeyRecieved* pkr = static_cast<PublicKeyRecieved*>(res.get());

		boost::asio::read(s, boost::asio::buffer(pkr->client_id, Constants::Sizes_In_Bytes::CLIENT_ID));

		// Todo: debug this part to see it works correctly:
		int encrypted_aes_key_length = res->header.payload_size - Constants::Sizes_In_Bytes::CLIENT_ID;
		std::vector<char> encrypted_aes_key_vector(encrypted_aes_key_length);

		boost::asio::read(s, boost::asio::buffer(&encrypted_aes_key_vector, encrypted_aes_key_length));

		u->decrypt_key(pkr->decrypted_aes_key, Constants::Sizes_In_Bytes::AES_KEY, encrypted_aes_key_vector);
	}
	
	else {
		boost::asio::read(s, boost::asio::buffer(res.get() + sizeof(ResponseHeader), sizeof(sizeofTable.at(header.code)) - sizeof(ResponseHeader)));
	}

	//if(!Endian::is_little_endian()) {
	//	if(header.code == Constants::Responses::codes::FileRecieved) { // The order is important because we flip header.code next. keep this if statement here.
	//		FileRecieved* temp = static_cast<FileRecieved*>(res.get());
	//		Endian::flip_endianness(temp->content_size);
	//		Endian::flip_endianness(temp->checksum);
	//	}
	//	Endian::flip_endianness(header.code);
	//	Endian::flip_endianness(header.version);
	//	Endian::flip_endianness(header.payload_size);
	//}
	return res;
}