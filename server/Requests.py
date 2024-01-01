
from abc import ABC
from typing import Type

Header_Size = 20

class Request:
    client_id:str
    version:int
    code: int
    payload_size:int
    payload:"RequestPayload"

class RequestPayload(ABC):
    pass

class Registration(RequestPayload):
    name:str

class PublicKeyTransfer(RequestPayload):
    name:str
    public_key:str

class Relogin(RequestPayload):
    name:str

class FileTransfer(RequestPayload):
    content_size:int
    original_file_size:int
    packet_number:int
    total_packets:int
    file_name:str
    message_content:str

class ValidCRC(RequestPayload):
    file_name:str

class InvalidCRC(RequestPayload):
    file_name:str

class InvalidCRCFourthTime(RequestPayload):
    file_name:str
