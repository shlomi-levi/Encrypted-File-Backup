#include <iostream>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <exception>

#include "User.h"
#include "Utilities.h"
#include "Requests.h"
#include "Responses.h"
#include "Base64Wrapper.h"
#include "checksum.h"

// TODO: Add saving of user details in a file

using std::cerr;
using std::cout;
using std::endl;
using std::cbegin;
using std::cend;

User::User(string server_address, string server_port, string user_name, string file_path, string user_uuid, string private_key) : aes_object(nullptr) {
	has_uuid = false;

	if(user_name.length() > (Constants::Sizes_In_Bytes::CLIENT_NAME - 1)) // -1 for \0 character
		throw std::logic_error("User name is too long. it must be at most " + std::to_string(Constants::Sizes_In_Bytes::CLIENT_NAME - 1) + " characters.");

	user_name.copy(this->name, user_name.length());
	this->name[user_name.length()] = '\0';

	this->file_path = file_path;
	this->server_address = server_address;
	this->server_port = server_port;

	if(user_uuid != "") {
		has_uuid = true;

		std::vector<char> uuid_bytes = Hex::hex_string_to_bytes(user_uuid);
		
		if(uuid_bytes.size() != Constants::Sizes_In_Bytes::CLIENT_ID)
			throw std::logic_error("Invalid uuid provided in the file" + Constants::ME_FILE_PATH);

		for(int i = 0 ; i < Constants::Sizes_In_Bytes::CLIENT_ID ; i++)
			uuid[i] = uuid_bytes[i];
	}

	if(private_key != "")
		rsa_object = std::make_unique<RSAPrivateWrapper>(private_key);
	
	else
		rsa_object = std::make_unique<RSAPrivateWrapper>();

	get_file_name();

}

void User::get_file_name() {
	size_t offset = 0;
	size_t temp = this->file_path.find("\\", offset);

	string fname;

	if(temp == std::string::npos)
		fname = this->file_path;

	else {
		while(temp != std::string::npos) {
			offset = temp;
			temp = this->file_path.find("\\", offset);
		}

		fname = this->file_path.substr(offset + 1);
	}

	copy_from_string_to_array(this->file_name, Constants::Sizes_In_Bytes::FILE_NAME, fname, true);
}

void User::handle_relogin(tcp::socket& s) {
	Relogin relogin_req {*this};
	boost::asio::write(s, boost::asio::buffer(relogin_req.pack()));

	std::unique_ptr<Response> res = Response::get_response(s);

	if(res->header.code == Constants::Responses::codes::DeclineRelogin)
		return handle_registration(s);

	if(res->header.code == Constants::Responses::codes::GeneralServerError) {
		// Todo: decide what to do in case of server error.
	}

	if(res->header.code == Constants::Responses::codes::AllowRelogin) {
		AllowRelogin* relogin_response = static_cast<AllowRelogin*>(res.get());

		string decrypted_aes_key = rsa_object->decrypt(relogin_response->encrypted_aes_key);
		
		unsigned char key[Constants::Sizes_In_Bytes::AES_KEY];

		if(decrypted_aes_key.size() != Constants::Sizes_In_Bytes::AES_KEY) {
			throw std::logic_error("decrypted aes key size differs from " + Constants::Sizes_In_Bytes::AES_KEY);
		}

		for(int i = 0; i < decrypted_aes_key.size(); i++)
			key[i] = decrypted_aes_key[i];

		aes_object = std::make_unique<AESWrapper>(key, Constants::Sizes_In_Bytes::AES_KEY);

		std::copy(relogin_response->client_id, relogin_response->client_id + Constants::Sizes_In_Bytes::CLIENT_ID, uuid);

		return;
	}
}

void User::handle_public_key_transfer(tcp::socket& s) {
	PublicKeyTransfer public_key_transfer_req {*this};
	boost::asio::write(s, boost::asio::buffer(public_key_transfer_req.pack()));

	unique_ptr<Response> res = Response::get_response(s);

	if(res->header.code == Constants::Responses::codes::PublicKeyRecieved) {
		PublicKeyRecieved* pkr = static_cast<PublicKeyRecieved*>(res.get());

		string decrypted_aes_key = rsa_object->decrypt(pkr->encrypted_aes_key);

		unsigned char key[Constants::Sizes_In_Bytes::AES_KEY];

		if(decrypted_aes_key.size() != Constants::Sizes_In_Bytes::AES_KEY) {
			throw std::logic_error("decrypted aes key size differs from " + Constants::Sizes_In_Bytes::AES_KEY);
		}

		for(int i = 0 ; i < decrypted_aes_key.size() ; i++)
			key[i] = decrypted_aes_key[i];

		aes_object = std::make_unique<AESWrapper>(key, Constants::Sizes_In_Bytes::AES_KEY);

		std::copy(pkr->client_id, pkr->client_id + Constants::Sizes_In_Bytes::CLIENT_ID, uuid);

		return;
	}

	else if(res->header.code == Constants::Responses::codes::GeneralServerError) {
		// Todo: throw error.
	}
}

void User::handle_registration(tcp::socket& s) {
	Registration registration_req {*this};

	std::vector<uint8_t> packed = registration_req.pack();

	boost::asio::write(s, boost::asio::buffer(packed));

	unique_ptr<Response> res = Response::get_response(s);

	if(res->header.code == Constants::Responses::codes::GeneralServerError) {
		// Todo: decide what to do in case of Server Error.
		return;
	}

	if(res->header.code == Constants::Responses::codes::RegistrationFailure) {
		// Todo: decide what to do in case of registration failure
		return;
	}

	if(res->header.code == Constants::Responses::codes::RegistrationSuccess) {
		RegistrationSuccess* reg_success = static_cast<RegistrationSuccess*>(res.get());
		std::copy(reg_success->client_id, reg_success->client_id + Constants::Sizes_In_Bytes::CLIENT_ID, uuid);
		
		return handle_public_key_transfer(s);
	}
}

void User::handle_file_transfer(tcp::socket& s) {
	std::ifstream f;

	uint8_t buffer[Constants::Sizes_In_Bytes::FILE_TRANSFER_BUFFER];

	try {
		f.open(file_name, std::ios::in | std::ios::binary);

		if(!f.is_open()) {
			throw std::logic_error("Couldn't open the file " + Constants::TRANSFER_FILE_PATH);
			exit(1);
		}

		uint16_t packet_count = 0;

		std::filesystem::path _path(file_name);

		float _total_packets = float(std::filesystem::file_size(_path)) / Constants::Sizes_In_Bytes::FILE_TRANSFER_BUFFER;

		uint16_t total_packets = static_cast<uint16_t>(int(ceil(_total_packets)));

		while(!f.eof()) {
			packet_count += 1;

			f.read(reinterpret_cast<char*>(buffer), Constants::Sizes_In_Bytes::FILE_TRANSFER_BUFFER);

			unsigned int length = f.gcount();

			string encrypted_text = aes_object->encrypt(reinterpret_cast<char*>(buffer), length);
			
			FileTransfer req {*this, static_cast<uint32_t>(length), packet_count, total_packets, encrypted_text};

			boost::asio::write(s, boost::asio::buffer(req.pack()));
		}
	}

	catch(const std::exception& e) {
		cerr << e.what() << endl;
		if(s.is_open())
			s.close();

		if(f.is_open())
			f.close();

		exit(1);
	}

	f.close();
}

void User::start() {
	boost::asio::io_context io_context;
	tcp::socket s(io_context);
	tcp::resolver resolver(io_context);
	
	try {
		boost::asio::connect(s, resolver.resolve(server_address, server_port));

		if(has_uuid)
			handle_relogin(s);

		else
			handle_registration(s);

		cout << "Client is now logged in, and keys were transferred" << endl;
		cout << "Transferring file:" << endl;

		// Now the client is logged in and has a key.
		unsigned long checksum_result = calculate_crc(file_name);

		int failed_transfers_counter = 0;

		while(failed_transfers_counter < Constants::TRANSFER_RETRY_COUNT) {
			handle_file_transfer(s);
			
			std::unique_ptr<Response> res = Response::get_response(s);

			if(res->header.code == Constants::Responses::codes::GeneralServerError) {
				// Todo: decide how to handle this error.
			}

			if(res->header.code == Constants::Responses::codes::FileRecieved) {
				FileRecieved* fr = static_cast<FileRecieved*>(res.get());
				if(fr->checksum == checksum_result) {
					cout << "File transferred successfully." << endl;
					ValidCRC req {*this};
					boost::asio::write(s, boost::asio::buffer(req.pack()));
					break;
				}

				cout << "Transfer failed, trying again." << endl;
				failed_transfers_counter++;

				InvalidCRC req {*this};
				boost::asio::write(s, boost::asio::buffer(req.pack()));
			}
		}

		if(failed_transfers_counter == Constants::TRANSFER_RETRY_COUNT) {
			cout << "Transfer failed " << Constants::TRANSFER_RETRY_COUNT << " times." << endl;
			InvalidCRCFourthTime req {*this};
			boost::asio::write(s, boost::asio::buffer(req.pack()));
		}

		std::unique_ptr<Response> res = Response::get_response(s);

		if(res->header.code != Constants::Responses::codes::MessageRecieved) {
			// Todo: decide how to handle this error.
		}
	}

	catch(const std::exception& e) {
		cerr << e.what() << endl;
		if(s.is_open())
			s.close();
		
		exit(1);
	}

	s.close();

	cout << "Program finished." << endl;
}