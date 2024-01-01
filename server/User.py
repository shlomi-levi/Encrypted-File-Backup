import uuid
from Crypto.Cipher import AES

class User:
    name:str
    UUID:uuid
    public_key:bytes
    AES_key:AES
