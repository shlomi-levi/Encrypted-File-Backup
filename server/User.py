import uuid
from Crypto.Cipher import AES

class User:
    name:str
    UUID:uuid
    public_key:bytes
    symmetric_AES_key:bytes # encrypted with public key

    def __init__(self, name, uuid, public_key, AES_key):
        self.name = name
        self.uuid = uuid
        self.public_key = public_key
        self.AES_key = AES_key
