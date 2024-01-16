from User import User
import uuid
import Requests
import Responses
import socket

from Crypto.Cipher import AES

class Server:
    users_map:dict[uuid]

    def wait_for_requests(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind( ('localhost', self.PORT))
            sock.listen()
            # sock.setblocking()
            conn, addr = sock.accept()
            # TODO: add support to multiple clients
            req:Requests.Request = Requests.Request.parse_request(conn)

    def start(self):
        self.wait_for_requests()

    def handle_login_request(self, req:Requests.Request) -> Responses.Response:
        user_uuid = uuid.uuid4()

        while user_uuid in self.users_map:
            user_uuid = uuid.uuid4()

        self.users_map[user_uuid] = User(req.payload.name, user_uuid, None, None)

        res = Responses.Response
        # TODO: send the client the hexdigest, and make sure it was sent.

    def handle_pubic_key_transfer_request(self, req:Requests.Request):
        if req.header.client_id not in self.users_map:
            # todo: Return error response or something (maybe response 1606, ask in forum)

        cipher = AES.new(req.payload.public_key, AES.MODE_EAX)


        # Encryption:
        # data = b'secret data'
        # ciphertext, tag = cipher.encrypt_and_digest(data)
