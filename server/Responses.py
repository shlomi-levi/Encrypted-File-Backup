from abc import ABC, abstractmethod
from enum import Enum
import Requests
import struct

class ResponseCodes(Enum):
    RegistrationSuccess = 1600
    RegistrationFailure = 1601
    PublicKeyRecieved = 1602
    FileRecieved = 1603
    MessageRecieved = 1604
    AllowRelogin = 1605
    DeclineRelogin = 1606
    GeneralServerError = 1607


class ResponseHeader:
    version:int
    code:ResponseCodes
    payload_size:int

    def __init__(self, version:int, code:ResponseCodes, payload_size:int):
        self.version = version
        self.code = code
        self.payload_size = payload_size

    def pack(self) -> bytes:
        # Small endian of:
            # version - 1 byte
            # code - 2 bytes
            # payload size - 4 bytes (unsigned)

        return struct.pack("<BHL", self.version, self.code, self.payload_size)

class ResponsePayload(ABC):
    @abstractmethod
    def pack(self) -> bytes:
        pass

class RegisterationSuccess(ResponsePayload):
    client_id:str

    @staticmethod
    def generate_payload(payload):
        pass

    def pack(self) -> bytes:
        # Small endian of:
            # client id - 16 bytes
        return struct.pack("<16s", self.client_id)

class RegistrationFailure(ResponsePayload):
    def pack(self) -> bytes:
        return bytes()

class PublicKeyRecieved(ResponsePayload):
    client_id:str
    EncryptedAESKey:bytes

    def pack(self) -> bytes:
        # Small endian of:
            # client id - 16 bytes
            # Encrypted AES Key
        # TODO: check how to pack this since we dont know the length of the AES key.

class FileRecieved(ResponsePayload):
    client_id:str
    content_size:int
    file_name:str
    checksum:int

    def pack(self) -> bytes:
        # Small endian of
            # client id - 16 bytes
            # content size - 4 bytes
            # file name - 255 bytes
            # cksum - 4 bytes
        return struct.pack("<16sI255s4s", self.client_id, self.content_size, self.file_name, self.checksum)

class MessageRecieved(ResponsePayload):
    client_id:str

    def pack(self) -> bytes:
        # Small endian of:
        # client id - 255 bytes
        return struct.pack("<255s", self.client_id)

class AllowRelogin(ResponsePayload):
    client_id:str
    EncryptedAESKey:bytes

    def pack(self) -> bytes:
        # Small endian of:
            # client id - 16 bytes
            # Encrypted AES key -

        # TODO: check how to pack this since we dont know the length of the AES key..

class DeclineReLogin(ResponsePayload):
    client_id:str

    def pack(self) -> bytes:
        # Small endian of:
            # client id - 16 bytes
        return struct.pack("<16s", self.client_id)

class GeneralServerError(ResponsePayload):
    def pack(self) -> bytes:
        return bytes()

class Response:
    header:ResponseHeader
    payload:ResponsePayload

    def __init__(self, header:ResponseHeader, payload:ResponsePayload):
        self.header = header
        self.payload = payload

    def pack(self):
        packed_header = self.header.pack()
        packed_payload = self.payload.pack()

        # TODO: concatenate header and payload, and return result

    @staticmethod
    def generate_response(req:Requests.Request) -> "Response":
        # TODO: I need to think about how to implement this.
        header =
