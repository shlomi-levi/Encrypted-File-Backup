#include <iostream>
#include <filesystem>
#include <fstream>
#include <exception>
#include "User.h"
#include "Protocol.h"
#include "Utilities.h"
#include "Requests.h"
#include "Responses.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"

// Todo: add header guards for all header files (lo kashur la kovez haze)

using std::cerr;
using std::cout;
using std::endl;

User::User(string server_address, string server_port, string user_name, string file_path, string user_uuid="", string private_key="") {
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

string User::get_file_name() {
	int offset = 0;
	int temp = this->file_path.find("\\", offset);

	while(temp != std::string::npos) {
		offset = temp;
		temp = this->file_path.find("\\", offset);
	}

	string fname = this->file_path.substr(offset + 1);

	copy_from_string_to_array(this->file_name, Constants::Sizes_In_Bytes::FILE_NAME, fname, true);
}

void User::handle_relogin(tcp::socket& s) {
	Relogin relogin_req {*this};
	boost::asio::write(s, boost::asio::buffer(&relogin_req, sizeof(relogin_req)));

	std::unique_ptr<Response> res = Response::get_response(s);

	if(res->header.code == Constants::Responses::codes::DeclineRelogin)
		return handle_registration(s);

	if(res->header.code == Constants::Responses::codes::GeneralServerError) {
		// Todo: decide what to do in case of server error.
	}

	if(res->header.code == Constants::Responses::codes::AllowRelogin) {
		AllowRelogin* relogin_response = static_cast<AllowRelogin*>(res.get());
		aes_object = std::make_unique<AESWrapper>(relogin_response->EncryptedAESKey, Constants::Sizes_In_Bytes::AES_KEY);

		std::copy(relogin_response->client_id, relogin_response->client_id + Constants::Sizes_In_Bytes::CLIENT_ID, uuid);

		return;
	}
}

void User::handle_public_key_transfer(tcp::socket& s) {
	PublicKeyTransfer public_key_transfer_req {*this};
	boost::asio::write(s, boost::asio::buffer(&public_key_transfer_req, sizeof(public_key_transfer_req)));

	unique_ptr<Response> res = Response::get_response(s);

	if(res->header.code == Constants::Responses::codes::PublicKeyRecieved) {
		PublicKeyRecieved* pkr = static_cast<PublicKeyRecieved*>(res.get());

		aes_object = std::make_unique<AESWrapper>(pkr->decrypted_aes_key, Constants::Sizes_In_Bytes::AES_KEY);
		return;
	}

	else if(res->header.code == Constants::Responses::codes::GeneralServerError) {
		// Todo: throw error.
	}
}

void User::handle_registration(tcp::socket& s) {
	Registration registration_req {*this};
	boost::asio::write(s, boost::asio::buffer(&registration_req, sizeof(registration_req)));

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

	char buffer[Constants::Sizes_In_Bytes::FILE_TRANSFER_BUFFER];

	try {
		f.open(file_name, std::ios::in);

		if(!f.is_open()) {
			throw std::logic_error("Couldn't open the file " + Constants::TRANSFER_FILE_PATH);
			exit(1);
		}

		int packet_count = 0;
		int total_packets = ceil(std::filesystem::file_size(file_name) / Constants::Sizes_In_Bytes::FILE_TRANSFER_BUFFER);

		while(!f.eof()) {
			packet_count += 1;

			f.read(buffer, Constants::Sizes_In_Bytes::FILE_TRANSFER_BUFFER);
			string encrypted_text = aes_object->encrypt(buffer, f.gcount());

			FileTransfer req {*this, encrypted_text.size(), f.gcount(), packet_count, total_packets};

			boost::asio::write(s, boost::asio::buffer(&req, sizeof(FileTransfer)));
			boost::asio::write(s, boost::asio::buffer(&encrypted_text, encrypted_text.size()));
		}
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

		// Now the client is logged in and has a key.
		handle_file_transfer(s);
		// Todo: continue this.
	}

	catch(const std::exception& e) {
		cerr << e.what() << endl;
		if(s.is_open())
			s.close();
		
		exit(1);
	}

	s.close();
}