from User import User
import uuid
import Requests
import Responses
import socket
from constants import *

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# TODO: GO OVER ALL HANDLERS AGAIN TO SEE I DIDNT MISS SOMETHING.

class Server:
    users_map:dict[uuid, User]
    PORT:int
    def __init__(self, PORT):
        self.PORT = PORT

    def wait_for_requests(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind( ('localhost', self.PORT))
            sock.listen()
            # sock.setblocking()
            conn, addr = sock.accept()
            # TODO: add support to multiple clients
            req:Requests.Request = Requests.parse_request(conn)

            handler_dict = {
                RequestCodes.REGISTRATION : self.handle_registration_request,
                RequestCodes.PUBLIC_KEY_TRANSFER: self.handle_public_key_transfer_request,
                RequestCodes.RELOGIN: self.handle_relogin_request,
                RequestCodes.FILETRANSFER: self.handle_file_transfer_request,
                RequestCodes.VALIDCRC: self.handle_valid_crc_reqeust,
                RequestCodes.INVALIDCRC: self.handle_invalid_crc_request,
                RequestCodes.INVALIDCRCFOURTHTIME: self.handle_invalid_crc_fourth_time_request
            }

            response = handler_dict[req.header.code](req) # type:ignore
            sock.sendall(response.pack())

    def start(self):
        self.wait_for_requests()

    def handle_registration_request(self, req:Requests.Registration) -> Responses.Response:
        user_uuid = uuid.uuid4().bytes.decode()

        while user_uuid in self.users_map:
            user_uuid = uuid.uuid4().bytes.decode()

        self.users_map[user_uuid] = User(req.name, user_uuid, None, None)

        res = Responses.RegisterationSuccess(user_uuid)

        return res

    def handle_public_key_transfer_request(self, req:Requests.PublicKeyTransfer) -> Responses.Response:
        if req.header.client_id not in self.users_map:
            return Responses.GeneralServerError()

        u:User = self.users_map[req.header.client_id]
        u.public_key = req.public_key

        aes_key = get_random_bytes(SYMMETRIC_AES_KEY_LENGTH)
        u.aes_key = aes_key

        rsa_encrypter = PKCS1_OAEP.new(RSA.importKey(req.public_key))
        encrypted_aes_key:bytes = rsa_encrypter.encrypt(aes_key)

        return Responses.PublicKeyRecieved(req.header.client_id, encrypted_aes_key)

    def handle_relogin_request(self, req:Requests.Relogin) -> Responses.Response:
        cid = req.header.client_id

        if cid not in self.users_map or not self.users_map[cid].public_key:
            return Responses.DeclineReLogin(cid)

        user = self.users_map[cid]
        rsa_encrypter = PKCS1_OAEP.new(RSA.importKey(user.public_key))
        encrypted_aes_key: bytes = rsa_encrypter.encrypt(user.aes_key)

        return Responses.AllowRelogin(cid, encrypted_aes_key)

    def handle_file_transfer_request(self, req:Requests.FileTransfer) -> Responses.Response:
        file =
        pass

    def handle_valid_crc_reqeust(self, req:Requests.ValidCRC) -> Responses.Response:

        pass

    def handle_invalid_crc_request(self, req:Requests.InvalidCRC) -> Responses.Response:
        pass

    def handle_invalid_crc_fourth_time_request(self, req:Requests.InvalidCRCFourthTime) -> Responses.Response:
        pass