
import constants
import struct

from abc import ABC, abstractmethod

class ResponseHeader:
    code:int
    payload_size:int

    def __init__(self, code:int, payload_size:int):
        self.code = code
        self.payload_size = payload_size

    def pack(self) -> bytes:
        # Small endian of:
            # version - 1 byte
            # code - 2 bytes
            # payload size - 4 bytes (unsigned)

        return struct.pack("<BHL", constants.SERVER_VERSION, self.code, self.payload_size)

class Response(ABC):
    header:ResponseHeader

    def pack(self) -> bytes:
        return self.header.pack() + self.pack_payload()

    @abstractmethod
    def pack_payload(self) -> bytes:
        pass

class RegisterationSuccess(Response):
    client_id:str

    def pack_payload(self) -> bytes:
        # Small endian of:
            # client id - 16 bytes
        return struct.pack(f"<{constants.FieldsSizes.CLIENT_ID}s", self.client_id)

    def __init__(self, client_id:str):
        PAYLOAD_SIZE = constants.FieldsSizes.CLIENT_ID

        self.header = ResponseHeader(constants.ResponseCodes.RegistrationSuccess, PAYLOAD_SIZE)
        self.client_id = client_id

class RegistrationFailure(Response):
    def pack_payload(self) -> bytes:
        return bytes()

    def __init__(self):
        self.header = ResponseHeader(constants.ResponseCodes.RegistrationFailure, 0)

class PublicKeyRecieved(Response):
    client_id:str
    encrypted_aes_key:bytes

    def pack_payload(self) -> bytes:
        # Small endian of:
            # client id
            # encrypted_aes_key - dynamic size.
        return struct.pack(f"<{constants.FieldsSizes.CLIENT_ID}s{len(self.encrypted_aes_key)}s", self.client_id, self.encrypted_aes_key)

    def __init__(self, client_id: str, encrypted_aes_key:bytes):
        payload_size = constants.FieldsSizes.CLIENT_ID + len(encrypted_aes_key)

        self.header = ResponseHeader(constants.ResponseCodes.PublicKeyRecieved, payload_size)
        self.client_id = client_id
        self.encrypted_aes_key = encrypted_aes_key

class FileRecieved(Response):
    client_id:str
    content_size:int
    file_name:str
    checksum:int

    def pack_payload(self) -> bytes:
        # Small endian of
            # client id - 16 bytes
            # content size - 4 bytes
            # file name - 255 bytes
            # cksum - 4 bytes
        # TODO: work on this
        return struct.pack("<16sI255sL", self.client_id, self.content_size, self.file_name, self.checksum)

    def __init__(self, client_id:str, content_size:int, file_name:str, cksum:int):
        PAYLOAD_SIZE:int = constants.FieldsSizes.CLIENT_ID + constants.FieldsSizes.CONTENT_SIZE + constants.FieldsSizes.FILE_NAME + constants.FieldsSizes.CHECKSUM

        self.header = ResponseHeader(constants.ResponseCodes.FileRecieved, PAYLOAD_SIZE)
        self.client_id = client_id
        self.content_size = content_size
        self.file_name = file_name
        self.checksum = cksum

class MessageRecieved(Response):
    client_id:str

    def pack_payload(self) -> bytes:
        # Small endian of:
        # client id
        return struct.pack(f"<{constants.FieldsSizes.CLIENT_ID}s", self.client_id)

    def __init__(self, client_id:str):
        PAYLOAD_SIZE = constants.FieldsSizes.CLIENT_ID

        self.header = ResponseHeader(constants.ResponseCodes.MessageRecieved, PAYLOAD_SIZE)
        self.client_id = client_id

class AllowRelogin(Response):
    client_id:str
    encrypted_aes_key:bytes

    def pack_payload(self) -> bytes:
        # Small endian of:
            # client id
            # encrypted aes key

        return struct.pack(f"<{constants.FieldsSizes.CLIENT_ID}s{len(self.encrypted_aes_key)}s", self.client_id,
            self.encrypted_aes_key)

    def __init__(self, client_id: str, encrypted_aes_key:bytes):
        payload_size = constants.FieldsSizes.CLIENT_ID + len(encrypted_aes_key)
        self.header = ResponseHeader(constants.ResponseCodes.AllowRelogin, payload_size)

        self.client_id = client_id
        self.encrypted_aes_key = encrypted_aes_key

class DeclineReLogin(Response):
    client_id:str

    def pack_payload(self) -> bytes:
        # Small endian of:
            # client id
        return struct.pack(f"<{constants.FieldsSizes.CLIENT_ID}s", self.client_id)

    def __init__(self, client_id:str):
        self.header = ResponseHeader(constants.ResponseCodes.DeclineRelogin, constants.FieldsSizes.CLIENT_ID)
        self.client_id = client_id

class GeneralServerError(Response):
    def pack_payload(self) -> bytes:
        return bytes()

    def __init__(self):
        self.header = ResponseHeader(constants.ResponseCodes.GeneralServerError, 0)
