from User import User
import uuid
import Requests
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


    def handle_login_request(self, req:Requests.Request):
        user_uuid = uuid.uuid4()

        while user_uuid in self.users_map:
            user_uuid = uuid.uuid4()

        cipher = AES.new(public_key, AES.MODE_EAX)
        # TODO: send the client the hexdigest, and make sure it was sent.


        self.users_map[user_uuid] = User(name, user_uuid, public_key, cipher)




        # Encryption:
        # data = b'secret data'
        # ciphertext, tag = cipher.encrypt_and_digest(data)
