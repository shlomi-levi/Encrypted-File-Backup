
# TODO: check that name fields are null terminated. I might have to do this in the cpp code instead of here. i need to think about it

from abc import ABC, abstractmethod
import struct
from constants import *

Header_Size = 23
Header_Client_Id_Size = 16
Header_Version_Size = 1
Header_Code_Size = 2
Header_Payload_Size = 4

class RequestHeader:
    client_id: str
    version: int
    code: Request_Codes
    payload_size: int

    def __init__(self, clientid:str, version:int, code:Request_Codes, payloadsize:int):
        self.client_id = clientid
        self.version = version
        self.code = code
        self.payload_size = payloadsize

class Request(ABC):
    header:RequestHeader

    @staticmethod
    @abstractmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes):
        pass

class Registration(Request):
    name:str

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        client_name = struct.unpack("<s", payload)[0]

        return Registration(header, client_name)

    def __init__(self, header:RequestHeader, client_name):
        self.header = header
        self.name = client_name

class PublicKeyTransfer(Request):
    name:str
    public_key:str

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        client_name_size = 255
        public_key_size = 160

        client_name = struct.unpack(f"<{client_name_size}s", payload)[0]
        payload = payload[client_name_size:]

        public_key = struct.unpack(f"<{public_key_size}s", payload)[0]

        return PublicKeyTransfer(header, client_name, public_key)

    def __init__(self, header:RequestHeader, client_name, public_key):
        self.header = header
        self.client_name = client_name
        self.public_key = public_key

class Relogin(Request):
    name:str

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        client_name = struct.unpack("<s", payload)[0]

        return Relogin(header, client_name)

    def __init__(self, header:RequestHeader, client_name):
        self.header = header
        self.client_name = client_name

class FileTransfer(Request):
    content_size:int
    original_file_size:int
    packet_number:int
    total_packets:int
    file_name:str
    message_content:bytes

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        content_size_field_length = 4
        original_size_field_length = 4
        packet_number_field_length = 2
        total_packets_field_length = 2
        file_name_field_length = 255

        content_size, original_size, packet_number, total_packets = struct.unpack("<IIHH", payload)

        payload = payload[content_size_field_length + original_size_field_length + packet_number_field_length + total_packets_field_length:]

        file_name = struct.unpack(f"<{file_name_field_length}s", payload)[0]

        payload = payload[file_name_field_length:]

        message_content = struct.unpack("<", payload)[0]

        return FileTransfer(header, content_size, original_size, packet_number, total_packets, file_name, message_content)

    def __init__(self, header:RequestHeader, content_size, original_file_size, packet_number, total_packets, file_name, message_content):
        self.header = header
        self.content_size = content_size
        self.original_file_size = original_file_size
        self.packet_number = packet_number
        self.total_packets = total_packets
        self.file_name = file_name
        self.message_content = message_content

class ValidCRC(Request):
    file_name:str

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        file_name_field_length = 255
        file_name = struct.unpack(f"<{file_name_field_length}s", payload)[0]

        return ValidCRC(header, file_name)
    def __init__(self, header:RequestHeader, file_name):
        self.header = header
        self.file_name = file_name

class InvalidCRC(Request):
    file_name:str

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        file_name_field_length = 255
        file_name = struct.unpack(f"<{file_name_field_length}s", payload)[0]

        return ValidCRC(header, file_name)

    def __init__(self, header:RequestHeader, file_name):
        self.header = header
        self.file_name = file_name

class InvalidCRCFourthTime(Request):
    file_name:str

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        file_name_field_length = 255
        file_name = struct.unpack(f"<{file_name_field_length}s", payload)[0]

        return ValidCRC(header, file_name)

    def __init__(self, header:RequestHeader, file_name):
        self.header = header
        self.file_name = file_name

def parse_request(conn) -> Request:
    Request_Codes_To_Handlers = {
        Request_Codes.REGISTRATION: Registration.create_request_from_payload,
        Request_Codes.PUBLIC_KEY_TRANSFER: PublicKeyTransfer.create_request_from_payload,
        Request_Codes.RELOGIN: Relogin.create_request_from_payload,
        Request_Codes.FILETRANSFER: FileTransfer.create_request_from_payload,
        Request_Codes.VALIDCRC: ValidCRC.create_request_from_payload,
        Request_Codes.INVALIDCRC: InvalidCRC.create_request_from_payload,
        Request_Codes.INVALIDCRCFOURTHTIME: InvalidCRCFourthTime.create_request_from_payload
    }

    try:
        request_bytes = conn.recv(Header_Size)  # Get the header

        client_id = struct.unpack(f"<{Header_Client_Id_Size}s", request_bytes[:Header_Client_Id_Size])[0]

        version, code, payload_size = struct.unpack("<BHL", request_bytes[Header_Client_Id_Size:])

        if code not in Request_Codes_To_Handlers:
        # TODO: output error, invalid code

        if payload_size != desired_payload_size:
        # TODO: output error, invalid payload size

        header = RequestHeader(client_id, version, code, payload_size)

        payload_bytes: bytes = conn.recv(payload_size)

        return Request_Codes_To_Handlers[code](header, payload_bytes)

    except:
        return None

    return True



