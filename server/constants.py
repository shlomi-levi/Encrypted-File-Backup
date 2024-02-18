from enum import Enum

SERVER_VERSION = 3
SYMMETRIC_AES_KEY_LENGTH = 32
Client_ID_Length = 16

class ResponseCodes(Enum):
    RegistrationSuccess = 1600
    RegistrationFailure = 1601
    PublicKeyRecieved = 1602
    FileRecieved = 1603
    MessageRecieved = 1604
    AllowRelogin = 1605
    DeclineRelogin = 1606
    GeneralServerError = 1607

class Request_Codes(Enum):
    REGISTRATION = 1025
    PUBLIC_KEY_TRANSFER = 1026
    RELOGIN = 1027
    FILETRANSFER = 1028
    VALIDCRC = 1029
    INVALIDCRC = 1030
    INVALIDCRCFOURTHTIME = 1031