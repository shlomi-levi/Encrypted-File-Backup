from abc import ABC, abstractmethod
# import Requests
from constants import *
import struct

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

class Response(ABC):
    header:ResponseHeader

    @abstractmethod
    def pack(self) -> bytes:
        pass

class RegisterationSuccess(Response):
    client_id:str

    def pack(self) -> bytes:
        # Small endian of:
            # client id - 16 bytes
        return struct.pack("<16s", self.client_id)

    def __init__(self, client_id:str):
        PAYLOAD_SIZE = 16

        self.header = ResponseHeader(SERVER_VERSION, ResponseCodes.RegistrationSuccess, PAYLOAD_SIZE)

        self.client_id = client_id

class RegistrationFailure(Response):
    def pack(self) -> bytes:
        return bytes()

    def __init__(self):
        PAYLOAD_SIZE = 0

        self.header = ResponseHeader(SERVER_VERSION, ResponseCodes.RegistrationFailure, PAYLOAD_SIZE)

class PublicKeyRecieved(Response):
    client_id:str
    EncryptedAESKey:bytes

    def pack(self) -> bytes:
        # Small endian of:
            # client id - 16 bytes
            # Encrypted AES Key
        # TODO: check how to pack this since we dont know the length of the AES key.
        return None # type:ignore

    def __init__(self, payload_size: int, client_id: str, AES_key):
        # TODO: ADD CONSTANT PAYLOAD_SIZE HERE AND CHANGE THE WAY I CREATE A HEADER.
        self.header = ResponseHeader(SERVER_VERSION, ResponseCodes.PublicKeyRecieved, payload_size)

        self.client_id = client_id
        self.EncryptedAESKey = AES_key

class FileRecieved(Response):
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

    def __init__(self, client_id:str, content_size:int, file_name:str, cksum:int):
        PAYLOAD_SIZE = 16 + 4 + 255 + 4

        self.header = ResponseHeader(SERVER_VERSION, ResponseCodes.FileRecieved, PAYLOAD_SIZE)

        self.client_id = client_id
        self.content_size = content_size
        self.file_name = file_name
        self.checksum = cksum

class MessageRecieved(Response):
    client_id:str

    def pack(self) -> bytes:
        # Small endian of:
        # client id - 255 bytes
        return struct.pack("<255s", self.client_id)

    def __init__(self, client_id:str):
        PAYLOAD_SIZE = 16

        self.header = ResponseHeader(SERVER_VERSION, ResponseCodes.MessageRecieved, PAYLOAD_SIZE)

        self.client_id = client_id

class AllowRelogin(Response):
    client_id:str
    EncryptedAESKey:bytes

    def pack(self) -> bytes:
        # Small endian of:
            # client id - 16 bytes
            # Encrypted AES key -

        # TODO: check how to pack this since we dont know the length of the AES key..
        return None # type:ignore

    def __init__(self, payload_size: int, client_id: str, AES_Key):
        # TODO: ADD PAYLOAD_SIZE CONSTANT SO I COULD CALCULATE THE client_id + AES_KEY LENGTH
        self.header = ResponseHeader(SERVER_VERSION, ResponseCodes.AllowRelogin, payload_size)

        self.client_id = client_id
        self.EncryptedAESKey = AES_Key

class DeclineReLogin(Response):
    client_id:str

    def pack(self) -> bytes:
        # Small endian of:
            # client id - 16 bytes
        return struct.pack("<16s", self.client_id)

    def __init__(self, client_id:str):
        PAYLOAD_SIZE = 16

        self.header = ResponseHeader(SERVER_VERSION, ResponseCodes.DeclineRelogin, PAYLOAD_SIZE)

        self.client_id = client_id

class GeneralServerError(Response):
    def pack(self) -> bytes:
        return bytes()

    def __init__(self):
        PAYLOAD_SIZE = 0
        self.header = ResponseHeader(SERVER_VERSION, ResponseCodes.GeneralServerError, PAYLOAD_SIZE)
