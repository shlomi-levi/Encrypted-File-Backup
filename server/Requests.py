
# TODO: check that name fields are null terminated. I might have to do this in the cpp code instead of here. i need to think about it

# TODO: finish handle_request static methods

from abc import ABC, abstractmethod
import struct
from enum import Enum

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

    def __init__(self, clientid:str, version:int, code:int, payloadsize:int):
        self.client_id = clientid
        self.version = version
        self.code = code
        self.payload_size = payloadsize

class RequestPayload(ABC):
    @staticmethod
    @abstractmethod
    def parse_payload(payload: bytes) -> "RequestPayload":
        pass

class Registration(RequestPayload):
    name:str

    @staticmethod
    def parse_payload(payload:bytes) -> RequestPayload:
        client_name = struct.unpack("<s", payload)[0]

        return Registration(client_name)

    def __init__(self, client_name):
        self.name = client_name

class PublicKeyTransfer(RequestPayload):
    name:str
    public_key:str

    @staticmethod
    def parse_payload(payload:bytes) -> RequestPayload:
        client_name_size = 255
        public_key_size = 160

        client_name = struct.unpack(f"<{client_name_size}s", payload)[0]
        payload = payload[client_name_size:]

        public_key = struct.unpack(f"<{public_key_size}s", payload)[0]

        return PublicKeyTransfer(client_name, public_key)

    def __init__(self, client_name, public_key):
        self.client_name = client_name
        self.public_key = public_key

class Relogin(RequestPayload):
    name:str

    @staticmethod
    def parse_payload(payload:bytes) -> RequestPayload:
        client_name = struct.unpack("<s", payload)[0]

        return Relogin(client_name)

    def __init__(self, client_name):
        self.client_name = client_name

class FileTransfer(RequestPayload):
    content_size:int
    original_file_size:int
    packet_number:int
    total_packets:int
    file_name:str
    message_content:bytes

    @staticmethod
    def parse_payload(payload:bytes) -> RequestPayload:
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

        return FileTransfer(content_size, original_size, packet_number, total_packets, file_name, message_content)

    def __init__(self, content_size, original_file_size, packet_number, total_packets, file_name, message_content):
        self.content_size = content_size
        self.original_file_size = original_file_size
        self.packet_number = packet_number
        self.total_packets = total_packets
        self . file_name = file_name
        self.message_content = message_content

class ValidCRC(RequestPayload):
    file_name:str

    @staticmethod
    def parse_payload(payload:bytes) -> RequestPayload:
        file_name_field_length = 255
        file_name = struct.unpack(f"<{file_name_field_length}s", payload)[0]

        return ValidCRC(file_name)
    def __init__(self, file_name):
        self.file_name = file_name

class InvalidCRC(RequestPayload):
    file_name:str

    @staticmethod
    def parse_payload(payload:bytes) -> RequestPayload:
        file_name_field_length = 255
        file_name = struct.unpack(f"<{file_name_field_length}s", payload)[0]

        return ValidCRC(file_name)

    def __init__(self, file_name):
        self.file_name = file_name

class InvalidCRCFourthTime(RequestPayload):
    file_name:str

    @staticmethod
    def parse_payload(payload:bytes) -> RequestPayload:
        file_name_field_length = 255
        file_name = struct.unpack(f"<{file_name_field_length}s", payload)[0]

        return ValidCRC(file_name)

    def __init__(self, file_name):
        self.file_name = file_name

class Request:
    header:RequestHeader
    payload:RequestPayload

    def __init__(self, header:RequestHeader, payload:RequestPayload):
        self.header = header
        self.payload = payload

    Request_Codes_To_Handlers = {
        Request_Codes.REGISTRATION: Registration.parse_payload,
        Request_Codes.PUBLIC_KEY_TRANSFER: PublicKeyTransfer.parse_payload,
        Request_Codes.RELOGIN: Relogin.parse_payload,
        Request_Codes.FILETRANSFER: FileTransfer.parse_payload,
        Request_Codes.VALIDCRC: ValidCRC.parse_payload,
        Request_Codes.INVALIDCRC: InvalidCRC.parse_payload,
        Request_Codes.INVALIDCRCFOURTHTIME: InvalidCRCFourthTime.parse_payload
    }
    @staticmethod
    def parse_request(conn):
        try:
            request_bytes = conn.recv(Header_Size)  # Get the header

            client_id = struct.unpack(f"<{Header_Client_Id_Size}s", request_bytes[:Header_Client_Id_Size])[0]

            version, code, payload_size = struct.unpack("<BHL", request_bytes[Header_Client_Id_Size:])

            if code not in Request.Request_Codes_To_Handlers:
            # TODO: output error, invalid code

            if payload_size != desired_payload_size:
            # TODO: output error, invalid payload size

            payload_bytes:bytes = conn.recv(payload_size)

            header = RequestHeader(client_id, version, code, payload_size)

            payload: RequestPayload = Request.Request_Codes_To_Handlers[code](payload_bytes)

            return Request(header, payload)

        except:
            return None

        return True


