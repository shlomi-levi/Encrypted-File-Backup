#include "Responses.h"
#include "Utilities.h"

ResponseHeader& ResponseHeader::operator=(const ResponseHeader& other) {
	if(this == &other)
		return *this;

	version = other.version;
	code = other.code;
	payload_size = other.payload_size;

	return *this;
}

std::unique_ptr<Response> Response::get_response(tcp::socket& s, User* u=nullptr) {
	ResponseHeader header;
	boost::asio::read(s, boost::asio::buffer(&header, sizeof(header)));
	
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

		case default:
			// Todo: throw error.
	}

	res->header = header;

	if(header.code == Constants::Responses::codes::PublicKeyRecieved) {
		PublicKeyRecieved* pkr = static_cast<PublicKeyRecieved*>(res.get());

		boost::asio::read(s, boost::asio::buffer(pkr->client_id, Constants::Sizes_In_Bytes::CLIENT_ID));

		// Todo: debug this part to see it works correctly:
		int encrypted_aes_key_length = res->header.payload_size - Constants::Sizes_In_Bytes::CLIENT_ID;
		std::vector<char> encrypted_aes_key_vector(encrypted_aes_key_length);

		boost::asio::read(s, boost::asio::buffer(&encrypted_aes_key_vector, encrypted_aes_key_length));

		// Copy from the vector to a string
		string encrypted_aes_key_string = "";
		for(int i = 0 ; i < encrypted_aes_key_vector.size() ; i++)
			encrypted_aes_key_string += encrypted_aes_key_vector[i];

		string decrypted_aes_key = u->rsa_object->decrypt(encrypted_aes_key_string);
		
		if(decrypted_aes_key.size() != Constants::Sizes_In_Bytes::AES_KEY) {
			// Todo: Throw error that the encrypted size doesn't match the aes_key size.
		}

		copy_from_string_to_array(pkr->decrypted_aes_key, Constants::Sizes_In_Bytes::AES_KEY, decrypted_aes_key);
	}
	
	else {
		boost::asio::read(s, boost::asio::buffer(res.get() + sizeof(ResponseHeader), sizeof(sizeofTable.at(header.code)) - sizeof(ResponseHeader)));
	}

	if(!Endian::is_little_endian()) {
		if(header.code == Constants::Responses::codes::FileRecieved) { // The order is important because we flip header.code next. keep this if statement here.
			FileRecieved* temp = static_cast<FileRecieved*>(res.get());
			Endian::flip_endianness(temp->content_size);
			Endian::flip_endianness(temp->checksum);
		}
		Endian::flip_endianness(header.code);
		Endian::flip_endianness(header.version);
		Endian::flip_endianness(header.payload_size);
	}
	return res;
}