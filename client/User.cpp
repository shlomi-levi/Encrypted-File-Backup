#include <iostream>
#include <exception>
#include <boost/asio.hpp>
#include "User.h"
#include "Protocol.h"
#include "Utilities.h"
#include "Requests.h"
#include "Responses.h"
#include "Base64Wrapper.h"
#include "RSAWrapper.h"

using boost::asio::ip::tcp;
using std::cout;
using std::endl;

User::User(string server_address, string server_port, string user_name, string file_path, string user_uuid="", string private_key="") {

	if(user_name.length() > (Constants::CLIENT_NAME_LENGTH - 1)) // -1 for \0 character
		throw std::logic_error("User name is too long. it must be at most " + std::to_string(Constants::CLIENT_NAME_LENGTH - 1) + " characters.");

	user_name.copy(this->name, user_name.length());
	this->name[user_name.length()] = '\0';

	this->file_path = file_path;
	this->server_address = server_address;
	this->server_port = server_port;

	if(user_uuid != "") {
		std::vector<char> uuid_bytes = Hex::hex_string_to_bytes(user_uuid);
		
		if(uuid_bytes.size() != Constants::CLIENT_ID_LENGTH)
			throw std::logic_error("Invalid uuid provided in the file" + Constants::ME_FILE_PATH);

		for(int i = 0 ; i < Constants::CLIENT_ID_LENGTH ; i++)
			uuid[i] = uuid_bytes[i];
	}

	if(private_key != "")
		rsa_object = std::make_unique<RSAPrivateWrapper>(Base64Wrapper::decode(private_key));
	
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

	copy_from_string_to_array(this->file_name, Constants::FILE_NAME_LENGTH, fname, true);
}

void User::start() {
	boost::asio::io_context io_context;
	tcp::socket s(io_context);
	tcp::resolver resolver(io_context);
	
	try {
		boost::asio::connect(s, resolver.resolve(server_address, server_port));
	}

	catch(const std::exception& e) {
		cout << e.what() << endl;
		exit(1);
	}
}