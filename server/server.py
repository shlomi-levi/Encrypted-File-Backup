from User import User
import uuid
import Requests
import Responses
import socket
from constants import *
from os.path import basename, getsize
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from checksum import get_checksum

# TODO: GO OVER ALL HANDLERS AGAIN TO SEE I DIDNT MISS SOMETHING.

class Server:
    users_map:dict[uuid, User]
    PORT:int
    def __init__(self, PORT):
        self.users_map = {}
        self.PORT = PORT

    def wait_for_requests(self, conn):
        while True:
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

            response = handler_dict[req.header.code](req, conn) # type:ignore

            if response:
                conn.sendall(response.pack())

            if req.header.code == RequestCodes.VALIDCRC or req.header.code == RequestCodes.INVALIDCRCFOURTHTIME:
                conn.close()
                break


    def start(self):
        # TODO: add support to multiple clients
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(('localhost', self.PORT))
                sock.listen()
                conn, addr = sock.accept()
                self.wait_for_requests(conn)

        except Exception as e:
            print(e)
            if sock:
                sock.close()

    def handle_registration_request(self, req:Requests.Registration, conn) -> Responses.Response:
        user_uuid = uuid.uuid4().bytes

        while user_uuid in self.users_map:
            user_uuid = uuid.uuid4().bytes.decode()

        self.users_map[user_uuid] = User(req.name, user_uuid, None, None)

        res = Responses.RegisterationSuccess(user_uuid)

        return res

    def handle_public_key_transfer_request(self, req:Requests.PublicKeyTransfer, conn) -> Responses.Response:
        if req.header.client_id not in self.users_map:
            return Responses.GeneralServerError()

        u:User = self.users_map[req.header.client_id]
        u.public_key = req.public_key

        aes_key = get_random_bytes(FieldsSizes.AES_KEY)
        u.aes_key = aes_key

        encrypted_aes_key:bytes = PKCS1_OAEP.new(RSA.importKey(req.public_key)).encrypt(aes_key)

        return Responses.PublicKeyRecieved(req.header.client_id, encrypted_aes_key)

    def handle_relogin_request(self, req:Requests.Relogin, conn) -> Responses.Response:
        cid = req.header.client_id

        if cid not in self.users_map or not self.users_map[cid].public_key:
            return Responses.DeclineReLogin(cid)

        user = self.users_map[cid]
        rsa_encrypter = PKCS1_OAEP.new(RSA.importKey(user.public_key))
        encrypted_aes_key: bytes = rsa_encrypter.encrypt(user.aes_key)

        return Responses.AllowRelogin(cid, encrypted_aes_key)

    def handle_file_transfer_request(self, req:Requests.FileTransfer, conn) -> Responses.Response:
        if req.header.client_id not in self.users_map:
            return Responses.GeneralServerError()

        file_path = "my_product.docx"
        # Todo: change this
        # file_path = f"{req.header.client_id}/{basename(req.file_name)}"

        user = self.users_map[req.header.client_id]
        cipher = AES.new(user.aes_key, AES.MODE_CBC, iv=b'\x00' * 16)

        f = None

        try:
            open_mode = "wb" if req.packet_number == 1 else "ab"

            f = open(file_path, open_mode)
            decrypted_message:bytes = cipher.decrypt(req.message_content)[0:req.original_file_size]
            f.write(decrypted_message) # type: ignore

            # TODO: REMEMBER TO CHECK IF I NEED TO CHANGE THIS:
            if req.packet_number >= req.total_packets:
                f.close()
                return Responses.FileRecieved(req.header.client_id, getsize(file_path), basename(req.file_name),
                get_checksum(file_path))
                # req = Requests.parse_request(conn)

        except:
            if f:
                f.close()

        if f:
            f.close()

        # return Responses.GeneralServerError() # TODO: CHECK IF i need this

    def handle_valid_crc_reqeust(self, req:Requests.ValidCRC, conn) -> Responses.Response:
        return Responses.MessageRecieved(req.header.client_id)

    def handle_invalid_crc_request(self, req:Requests.InvalidCRC, conn) -> Responses.Response:
        # We don't need to do anything in this case.
        return None # type:ignore

    def handle_invalid_crc_fourth_time_request(self, req:Requests.InvalidCRCFourthTime, conn) -> Responses.Response:
        return Responses.MessageRecieved(req.header.client_id)
