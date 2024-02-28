#include <iostream>
#include "Utilities.h"
#include "User.h"

int main() {
	client_info info = get_client_info();

	User u(info.server_ip, info.server_port, info.client_name, info.file_path, info.UUID, info.private_key);
	u.start();

	return 0;
}

