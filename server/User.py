import uuid

class User:
    name:str
    UUID:uuid
    public_key:bytes
    aes_key:bytes

    def __init__(self, name, user_id, public_key, AES_key):
        self.name = name
        self.user_id = user_id
        self.public_key = public_key
        self.AES_key = AES_key
