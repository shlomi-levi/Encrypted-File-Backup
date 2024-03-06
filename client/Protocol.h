#pragma once
#ifndef PROTOCOL
#define PROTOCOL
#include <iostream>

using std::string;

namespace Constants {
	constexpr char CLIENT_VERSION = '3';
	constexpr int CLIENT_ID_LENGTH = 16;
	constexpr int CLIENT_NAME_LENGTH = 255;
	constexpr int NUM_OF_BITS_IN_RSA_KEY = 1024;
	constexpr int NUM_OF_BITS_IN_AES_KEY = 256;
	constexpr int NUM_OF_BYTES_IN_AES_KEY = NUM_OF_BITS_IN_AES_KEY / 8;
	constexpr int PUBLIC_KEY_LENGTH_IN_BYTES = 128;
	constexpr int FILE_NAME_LENGTH = 255;
	constexpr int CONTENT_SIZE_LENGTH_IN_BYTES = 4;
	constexpr int ORIGINAL_FILE_SIZE_LENGTH_IN_BYTES = 4;
	constexpr int PACKET_NUMBER_LENGTH_IN_BYTES = 2;
	constexpr int TOTAL_PACKETS_LENGTH_IN_BYTES = 2;
	constexpr int CHECKSUM_SIZE_IN_BYTES = 4;

	constexpr int BUFFER_SIZE_FILE_TRANSFER = 4000;

	const string ME_FILE_PATH = "me.info";
	const string TRANSFER_FILE_PATH = "transfer.info";

	constexpr char EMPTY_STRING[CLIENT_NAME_LENGTH] = { 0 };

	namespace Requests {
		enum codes {
			Registration = 1025,
			PublicKeyTransfer = 1026,
			Relogin = 1027,
			FileTransfer = 1028,
			ValidCRC = 1029,
			InvalidCRC = 1030,
			InvalidCRCFourthTime = 1031
		};

		enum payload_sizes {
			Registration = CLIENT_NAME_LENGTH,
			PublicKeyTransfer = CLIENT_NAME_LENGTH + PUBLIC_KEY_LENGTH_IN_BYTES,
			Relogin = CLIENT_NAME_LENGTH,
			FileTransfer = CONTENT_SIZE_LENGTH_IN_BYTES + ORIGINAL_FILE_SIZE_LENGTH_IN_BYTES + PACKET_NUMBER_LENGTH_IN_BYTES + TOTAL_PACKETS_LENGTH_IN_BYTES + FILE_NAME_LENGTH + BUFFER_SIZE_FILE_TRANSFER,

			ValidCRC = CLIENT_NAME_LENGTH,
			InvalidCRC = CLIENT_NAME_LENGTH,
			InvalidCRCFourthTime = CLIENT_NAME_LENGTH
		};
	};

	namespace Responses {
		enum codes {
			RegistrationSucceeded = 1600,
			RegistrationFailed = 1601,
			PublicKeyRecieved = 1602,
			FileRecievedValidCRC = 1603,
			MessageRecieved = 1604,
			ReloginApproved = 1605,
			ReloginDenied = 1606,
			GeneralServerError = 1606
		};
		
		enum payload_sizes {
			RegistrationSuccedded = CLIENT_ID_LENGTH,
			RegistrationFailed = 0,
			PublicKeyRecieved = CLIENT_ID_LENGTH + NUM_OF_BYTES_IN_AES_KEY,
			FileRecievedValidCRC = CLIENT_ID_LENGTH + CONTENT_SIZE_LENGTH_IN_BYTES + FILE_NAME_LENGTH + CHECKSUM_SIZE_IN_BYTES,

			MessageRecieved = CLIENT_ID_LENGTH,
			ReloginApproved = CLIENT_ID_LENGTH + NUM_OF_BYTES_IN_AES_KEY,
			ReloginDenied = CLIENT_ID_LENGTH,
			GeneralServerError = 0
		};
	}
}
#endif
