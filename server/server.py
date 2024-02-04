from User import User
import uuid
import Requests
import Responses
import socket
from constants import *

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class Server:
    users_map:dict[uuid, User]

    def wait_for_requests(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind( ('localhost', self.PORT))
            sock.listen()
            # sock.setblocking()
            conn, addr = sock.accept()
            # TODO: add support to multiple clients
            req:Requests.Request = Requests.parse_request(conn)

            handler_dict = {
                Request_Codes.REGISTRATION : self.handle_registration_request,
                Request_Codes.PUBLIC_KEY_TRANSFER: self.handle_pubic_key_transfer_request,
                Request_Codes.RELOGIN: self.handle_relogin_request,
                Request_Codes.FILETRANSFER: self.handle_file_transfer_request,
                Request_Codes.VALIDCRC: self.handle_valid_crc_reqeust,
                Request_Codes.INVALIDCRC: self.handle_invalid_crc_request,
                Request_Codes.INVALIDCRCFOURTHTIME: self.handle_invalid_crc_fourth_time_request
            }

            handler_dict[req.header.code](req) # type:ignore

    def start(self):
        self.wait_for_requests()

    def handle_registration_request(self, req:Requests.Registration) -> Responses.Response:
        user_uuid = uuid.uuid4().bytes.decode()

        while user_uuid in self.users_map:
            user_uuid = uuid.uuid4().bytes.decode()

        self.users_map[user_uuid] = User(req.name, user_uuid, None, None)

        res = Responses.RegisterationSuccess(user_uuid)

        return res

    def handle_pubic_key_transfer_request(self, req:Requests.PublicKeyTransfer):
        if req.header.client_id not in self.users_map:
            # todo: Return error response or something (maybe response 1606, ask in forum)

        session_key = get_random_bytes(AES_Key_Length)

        encrypted_session_key = AES.new(req.public_key, AES.MODE_CBC).encrypt(session_key)

        self.users_map[req.header.client_id].AES_key = encrypted_session_key

    def handle_relogin_request(self, req:Requests.Relogin) -> Responses.Response:
        pass

    def handle_file_transfer_request(self, req:Requests.FileTransfer) -> Responses.Response:
        pass

    def handle_valid_crc_reqeust(self, req:Requests.ValidCRC) -> Responses.Response:
        pass

    def handle_invalid_crc_request(self, req:Requests.InvalidCRC) -> Responses.Response:
        pass

    def handle_invalid_crc_fourth_time_request(self, req:Requests.InvalidCRCFourthTime) -> Responses.Response:
        pass