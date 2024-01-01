from abc import ABC

class Response:
    version:int
    coide:int
    payload_size:int
    response_payload:"ResponsePayload"

class ResponsePayload(ABC):
    pass

class RegisterationSuccess(ResponsePayload):
    client_id:str

class RegistrationFailure(ResponsePayload):
    pass

class PublicKeyRecieved(ResponsePayload):
    client_id:str
    EncryptedAESKey: to do later

class FileRecieved(ResponsePayload):
    client_id:str
    content_size:int
    file_name:str
    checksum:int

class MessageRecieved(ResponsePayload):
    client_id:str

class AllowRelogin(ResponsePayload):
    client_id:str
    EncryptedAESKey: to do later

class DeclineReLogin(ResponsePayload):
    client_id:str

class GeneralServerError(ResponsePayload):
    add 
    pass