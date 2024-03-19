
SERVER_VERSION = 3
PORT_INFO_FILE = 'port.info'
DEFAULT_PORT = 1256

class Database:
    DATABASE_NAME = 'defensive.db'
    CLIENTS_TABLE_NAME = 'clients'
    FILES_TABLE_NAME = 'files'


class FieldsSizes:
    AES_KEY = 32
    HEADER = 23
    CLIENT_ID = 16
    CLIENT_NAME = 255
    SERVER_VERSION = 1
    CODE = 2
    PAYLOAD_SIZE = 4
    PUBLIC_KEY = 160
    CONTENT_SIZE = 4
    ORIGINAL_CONTENT_SIZE = 4
    PACKET_NUMBER = 2
    TOTAL_PACKETS = 2
    FILE_NAME = 255
    CHECKSUM = 4

class ResponseCodes:
    RegistrationSuccess = 1600
    RegistrationFailure = 1601
    PublicKeyRecieved = 1602
    FileRecieved = 1603
    MessageRecieved = 1604
    AllowRelogin = 1605
    DeclineRelogin = 1606
    GeneralServerError = 1607

class RequestCodes:
    REGISTRATION = 1025
    PUBLIC_KEY_TRANSFER = 1026
    RELOGIN = 1027
    FILETRANSFER = 1028
    VALIDCRC = 1029
    INVALIDCRC = 1030
    INVALIDCRCFOURTHTIME = 1031