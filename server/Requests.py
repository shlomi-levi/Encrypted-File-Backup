
from abc import ABC
import struct
from enum import Enum
from typing import Type

Header_Size = 23
Header_Client_Id_Size = 16
Header_Version_Size = 1
Header_Code_Size = 2
Header_Payload_Size = 4

class Request_Codes(Enum):
    REGISTRATION = 1025
    PUBLIC_KEY_TRANSFER = 1026
    RELOGIN = 1027
    FILETRANSFER = 1028
    VALIDCRC = 1029
    INVALIDCRC = 1030
    INVALIDCRCFOURTHTIME = 1031

class RequestHeader:
    client_id: str
    version: int
    code: int
    payload_size: int

    def __init__(self, clientid, version, code, payloadsize, payload):
        self.client_id = clientid
        self.version = version
        self.code = code
        self.payload_size = payloadsize
class Request:
    header:RequestHeader
    payload:"RequestPayload"

    def __init__(self, header, payload):
        self.header = header
        self.payload = payload

class RequestPayload(ABC):
    pass

class Registration(RequestPayload):
    name:str

    @staticmethod
    def handle_request(header:RequestHeader, payload):
        name = struct.unpack(f"<255s", payload)[0]

class PublicKeyTransfer(RequestPayload):
    name:str
    public_key:str

    @staticmethod
    def handle_request(header:RequestHeader, payload):

class Relogin(RequestPayload):
    name:str

    @staticmethod
    def handle_request(header:RequestHeader, payload):

class FileTransfer(RequestPayload):
    content_size:int
    original_file_size:int
    packet_number:int
    total_packets:int
    file_name:str
    message_content:str

    @staticmethod
    def handle_request(header:RequestHeader, payload):

class ValidCRC(RequestPayload):
    file_name:str

    @staticmethod
    def handle_request(header:RequestHeader, payload):

class InvalidCRC(RequestPayload):
    file_name:str

    @staticmethod
    def handle_request(header:RequestHeader, payload):

class InvalidCRCFourthTime(RequestPayload):
    file_name:str

    @staticmethod
    def handle_request(header:RequestHeader, payload):


Request_Codes_To_Handlers = {
    Request_Codes.REGISTRATION: Registration.handle_request,
    Request_Codes.PUBLIC_KEY_TRANSFER: PublicKeyTransfer.handle_request,
    Request_Codes.RELOGIN: Relogin.handle_request,
    Request_Codes.FILETRANSFER: FileTransfer.handle_request,
    Request_Codes.VALIDCRC: ValidCRC.handle_request,
    Request_Codes.INVALIDCRC: InvalidCRC.handle_request,
    Request_Codes.INVALIDCRCFOURTHTIME: InvalidCRCFourthTime.handle_request
}

def handle_request_header(conn):
    try:
        request_bytes = conn.recv(Header_Size)  # Get the header

        client_id = struct.unpack(f"<{Header_Client_Id_Size}s", request_bytes[:Header_Client_Id_Size])[0]

        version, code, payload_size = struct.unpack("<BHL", request_bytes[Header_Client_Id_Size:])

        payload = conn.recv(payload_size)

        header = RequestHeader(client_id, version, code, payload_size)

        if code not in Request_Codes_To_Handlers:
            # TODO: output error, invalid code

        output = Request_Codes_To_Handlers[code](header, payload)


    except:
        return None

    return True
