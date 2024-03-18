
from abc import ABC, abstractmethod
import struct
from constants import *

class RequestHeader:
    client_id: bytes
    version: int
    code: int
    payload_size: int

    def __init__(self, clientid:bytes, version:int, code:int, payloadsize:int):
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
        client_name = struct.unpack(f"{FieldsSizes.CLIENT_NAME}s", payload)[0]

        return Registration(header, client_name)

    def __init__(self, header:RequestHeader, client_name):
        self.header = header
        self.name = client_name

class PublicKeyTransfer(Request):
    name:str
    public_key:str

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        client_name, public_key = struct.unpack(f"{FieldsSizes.CLIENT_NAME}s{FieldsSizes.PUBLIC_KEY}s", payload)
        return PublicKeyTransfer(header, client_name, public_key)

    def __init__(self, header:RequestHeader, client_name, public_key):
        self.header = header
        self.client_name = client_name
        self.public_key = public_key

class Relogin(Request):
    name:str

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        client_name = struct.unpack(f"{FieldsSizes.CLIENT_NAME}s", payload)[0]

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
        offset = FieldsSizes.CONTENT_SIZE + FieldsSizes.ORIGINAL_CONTENT_SIZE + FieldsSizes.PACKET_NUMBER + FieldsSizes.TOTAL_PACKETS

        content_size, original_size, packet_number, total_packets = struct.unpack("<IIHH", payload[0:offset])

        payload = payload[offset:]

        offset = FieldsSizes.FILE_NAME

        file_name = struct.unpack(f"{FieldsSizes.FILE_NAME}s", payload[0:offset])[0].decode()

        payload = payload[offset:]

        # Todo: check this
        #  message_content = struct.unpack("<", payload)[0]
        message_content = payload

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
        file_name = struct.unpack(f"{FieldsSizes.FILE_NAME}s", payload)[0]

        return ValidCRC(header, file_name)
    def __init__(self, header:RequestHeader, file_name):
        self.header = header
        self.file_name = file_name

class InvalidCRC(Request):
    file_name:str

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        file_name = struct.unpack(f"{FieldsSizes.FILE_NAME}s", payload)[0]

        return ValidCRC(header, file_name)

    def __init__(self, header:RequestHeader, file_name):
        self.header = header
        self.file_name = file_name

class InvalidCRCFourthTime(Request):
    file_name:str

    @staticmethod
    def create_request_from_payload(header:RequestHeader, payload:bytes) -> Request:
        file_name = struct.unpack(f"{FieldsSizes.FILE_NAME}s", payload)[0]

        return ValidCRC(header, file_name)

    def __init__(self, header:RequestHeader, file_name):
        self.header = header
        self.file_name = file_name

def parse_request(conn) -> Request:
    Request_Codes_To_Handlers = {
        RequestCodes.REGISTRATION: Registration.create_request_from_payload,
        RequestCodes.PUBLIC_KEY_TRANSFER: PublicKeyTransfer.create_request_from_payload,
        RequestCodes.RELOGIN: Relogin.create_request_from_payload,
        RequestCodes.FILETRANSFER: FileTransfer.create_request_from_payload,
        RequestCodes.VALIDCRC: ValidCRC.create_request_from_payload,
        RequestCodes.INVALIDCRC: InvalidCRC.create_request_from_payload,
        RequestCodes.INVALIDCRCFOURTHTIME: InvalidCRCFourthTime.create_request_from_payload
    }

    try:
        request_bytes = conn.recv(FieldsSizes.HEADER)  # Get the header

        client_id, version, code, payload_size = struct.unpack(f"<{FieldsSizes.CLIENT_ID}sBHL", request_bytes)

        # if code not in Request_Codes_To_Handlers:
        # TODO: output error, invalid code

        # if payload_size != desired_payload_size:
        # TODO: output error, invalid payload size

        header = RequestHeader(client_id, version, code, payload_size)

        payload_bytes: bytes = conn.recv(payload_size)

        return Request_Codes_To_Handlers[code](header, payload_bytes)

    except Exception as e:
        print(e)
        return None # type: ignore




