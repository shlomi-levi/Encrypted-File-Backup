#pragma once
#ifndef PROTOCOL
#define PROTOCOL
#include <iostream>
#include <string>
#include <cstdint>

using std::string;

namespace Constants {
	namespace Sizes_In_Bits {
		constexpr int RSA_KEY = 1024;
		constexpr int AES_KEY = 256;
	};

	namespace Sizes_In_Bytes {
		constexpr int CLIENT_VERSION = 1;
		constexpr int CLIENT_ID = 16;
		constexpr int CLIENT_NAME = 255;

		constexpr int PUBLIC_KEY = 128;
		constexpr int AES_KEY = Sizes_In_Bits::AES_KEY / 8; // byte is always 8 bits.

		constexpr int FILE_NAME = 255;
		constexpr int FILE_CONTENT_SIZE = 4;
		constexpr int FILE_CONTENT_ORIGINAL_SIZE = 4;
		constexpr int FILE_TRANSFER_BUFFER = 4000;
		constexpr int CHECKSUM = 4;

		constexpr int PACKET_NUMBER = 2;
		constexpr int TOTAL_PACKETS = 2;
	};

	constexpr int8_t CLIENT_VERSION = 3;

	static_assert(sizeof(CLIENT_VERSION) == Sizes_In_Bytes::CLIENT_VERSION, "Client version constant has the wrong type. check Constants::SIZES_IN_BYTES::CLIENT_VERSION in 'Protocol.h' to see how many bytes it should have.");

	const string ME_FILE_PATH = "me.info";
	const string PRIV_KEY_PATH = "priv.key";
	const string TRANSFER_FILE_PATH = "transfer.info";

	constexpr char EMPTY_NAME[Sizes_In_Bytes::CLIENT_NAME] = { 0 };

	namespace Requests {
		constexpr int REQUEST_CODE_SIZE = 2;
		constexpr int REQUEST_PAYLOAD_SIZE = 4;

		constexpr int HEADER_SIZE = Sizes_In_Bytes::CLIENT_ID + Sizes_In_Bytes::CLIENT_VERSION +
			REQUEST_CODE_SIZE + REQUEST_PAYLOAD_SIZE;

		enum codes {
			Registration = 1025,
			PublicKeyTransfer = 1026,
			Relogin = 1027,
			FileTransfer = 1028,
			ValidCRC = 1029,
			InvalidCRC = 1030,
			InvalidCRCFourthTime = 1031
		};

		// TODO: CHECK IF I EVEN NEED THIS (I CAN MAYBE USE IT TO VERIFY RESPONSE PAYLOAD SIZES)
		enum payload_sizes {
			Registration = Sizes_In_Bytes::CLIENT_NAME,
			PublicKeyTransfer = Sizes_In_Bytes::CLIENT_NAME + Sizes_In_Bytes::PUBLIC_KEY,
			Relogin = Sizes_In_Bytes::CLIENT_NAME,

			FileTransfer = Sizes_In_Bytes::FILE_CONTENT_SIZE + Sizes_In_Bytes::FILE_CONTENT_ORIGINAL_SIZE +
			Sizes_In_Bytes::PACKET_NUMBER + Sizes_In_Bytes::TOTAL_PACKETS + Sizes_In_Bytes::FILE_NAME +
			Sizes_In_Bytes::FILE_TRANSFER_BUFFER,

			ValidCRC = Sizes_In_Bytes::CLIENT_NAME,
			InvalidCRC = Sizes_In_Bytes::CLIENT_NAME,
			InvalidCRCFourthTime = Sizes_In_Bytes::CLIENT_NAME
		};
	};

	namespace Responses {
		constexpr int RESPONSE_CODE_SIZE = 2;
		constexpr int RESPONSE_VERSION_SIZE = 1;
		constexpr int RESPONSE_PAYLOAD_SIZE = 4;
		
		constexpr int HEADER_SIZE = RESPONSE_VERSION_SIZE + RESPONSE_CODE_SIZE + RESPONSE_PAYLOAD_SIZE;

		enum codes {
			RegistrationSuccess = 1600,
			RegistrationFailure = 1601,
			PublicKeyRecieved = 1602,
			FileRecieved = 1603,
			MessageRecieved = 1604,
			AllowRelogin = 1605,
			DeclineRelogin = 1606,
			GeneralServerError = 1607
		};
		
		// TODO: CHECK IF I EVEN NEED THIS (I CAN MAYBE USE IT TO VERIFY RESPONSE PAYLOAD SIZES)
		enum payload_sizes {
			RegistrationSuccedded = Sizes_In_Bytes::CLIENT_ID,
			RegistrationFailure = 0,
			PublicKeyRecieved = Sizes_In_Bytes::CLIENT_ID + Sizes_In_Bytes::AES_KEY,
			
			FileRecieved = Sizes_In_Bytes::CLIENT_ID + Sizes_In_Bytes::FILE_CONTENT_SIZE
			+ Sizes_In_Bytes::FILE_NAME + Sizes_In_Bytes::CHECKSUM,

			MessageRecieved = Sizes_In_Bytes::CLIENT_ID,
			AllowRelogin = Sizes_In_Bytes::CLIENT_ID + Sizes_In_Bytes::AES_KEY,
			DeclineRelogin = Sizes_In_Bytes::CLIENT_ID,
			GeneralServerError = 0
		};
	}
}
#endif
