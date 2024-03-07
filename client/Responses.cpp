#include "Responses.h"


static Response get_response(tcp::socket& s) {
	ResponseHeader r;
	boost::asio::read(s, boost::asio::buffer(&r, sizeof(r)));
	
	// TODO: implement get_response
}