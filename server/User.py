class User:
    name:str
    user_id:bytes
    public_key:bytes
    AES_key:bytes

    def __init__(self, name:str, user_id:bytes, public_key:bytes, AES_key:bytes):
        self.name = name
        self.user_id = user_id
        self.public_key = public_key
        self.AES_key = AES_key