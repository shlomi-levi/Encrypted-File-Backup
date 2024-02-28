#pragma once
#ifndef Client_Constants
#define Client_Constants

using std::string;

namespace Constants {
	const char CLIENT_VERSION = '3';
	const int CLIENT_ID_LENGTH = 16;
	const int CLIENT_NAME_LENGTH = 255;
	const int NUM_OF_BITS_IN_RSA_KEY = 1024;
	constexpr int NUM_OF_BITS_IN_AES_KEY = 256;
	constexpr int NUM_OF_BYTES_IN_AES_KEY = NUM_OF_BITS_IN_AES_KEY / 8;
	const int PUBLIC_KEY_LENGTH_IN_BYTES = 128;
	const int FILE_NAME_LENGTH = 255;
	const int BUFFER_SIZE_FILE_TRANSFER = 4000;
	const string ME_FILE_PATH = "me.info";
	const string TRANSFER_FILE_PATH = "transfer.info";
}
#endif
