import uuid
import Requests
import Responses
import socket
import os
import db

from User import User
from constants import *
from os.path import basename, getsize
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from checksum import get_checksum
from threading import Thread

# TODO: GO OVER ALL HANDLERS AGAIN TO SEE I DIDNT MISS SOMETHING.

users_map:dict[uuid, User] = {}

def handle_registration_request(req:Requests.Registration) -> Responses.Response:
    user_uuid = uuid.uuid4().bytes

    while user_uuid in users_map:
        user_uuid = uuid.uuid4().bytes.decode()

    users_map[user_uuid] = User(req.name, user_uuid, None, None)

    res = Responses.RegisterationSuccess(user_uuid)

    return res

def handle_public_key_transfer_request(req:Requests.PublicKeyTransfer) -> Responses.Response:
    if req.header.client_id not in users_map:
        return Responses.GeneralServerError()

    u:User = users_map[req.header.client_id]
    u.public_key = req.public_key

    aes_key = get_random_bytes(FieldsSizes.AES_KEY)
    u.aes_key = aes_key

    encrypted_aes_key:bytes = PKCS1_OAEP.new(RSA.importKey(req.public_key)).encrypt(aes_key)

    return Responses.PublicKeyRecieved(req.header.client_id, encrypted_aes_key)

def handle_relogin_request(req:Requests.Relogin) -> Responses.Response:
    cid = req.header.client_id

    if cid not in users_map or not users_map[cid].public_key:
        return Responses.DeclineReLogin(cid)

    user = users_map[cid]
    rsa_encrypter = PKCS1_OAEP.new(RSA.importKey(user.public_key))
    encrypted_aes_key: bytes = rsa_encrypter.encrypt(user.aes_key)

    return Responses.AllowRelogin(cid, encrypted_aes_key)

def handle_file_transfer_request(req:Requests.FileTransfer) -> Responses.Response:
    if req.header.client_id not in users_map:
        return Responses.GeneralServerError()

    directory = f"{req.header.client_id.hex()}"

    if not os.path.exists(directory):
        os.makedirs(directory)

    file_path = f"{directory}\\{basename(req.file_name)}".rstrip('\x00')

    user = users_map[req.header.client_id]
    cipher = AES.new(user.aes_key, AES.MODE_CBC, iv=b'\x00' * 16)

    f = None

    try:
        open_mode = "wb" if req.packet_number == 1 else "ab"

        f = open(file_path, open_mode)
        decrypted_message:bytes = cipher.decrypt(req.message_content)[0:req.original_file_size]
        f.write(decrypted_message) # type: ignore

        if req.packet_number >= req.total_packets:
            f.close()
            return Responses.FileRecieved(req.header.client_id, getsize(file_path), basename(req.file_name.encode()),
            get_checksum(file_path))

    except Exception as e:
        print(e)
        if f:
            f.close()

    if f:
        f.close()

    # return Responses.GeneralServerError() # TODO: CHECK IF i need this

def handle_valid_crc_reqeust(req:Requests.ValidCRC) -> Responses.Response:
    return Responses.MessageRecieved(req.header.client_id)

def handle_invalid_crc_request(req:Requests.InvalidCRC) -> Responses.Response:
    # We don't need to do anything in this case.
    return None # type:ignore

def handle_invalid_crc_fourth_time_request(req:Requests.InvalidCRCFourthTime) -> Responses.Response:
    return Responses.MessageRecieved(req.header.client_id)

def wait_for_requests(conn):
    while True:
        req:Requests.Request = Requests.parse_request(conn)

        handler_dict = {
            RequestCodes.REGISTRATION : handle_registration_request,
            RequestCodes.PUBLIC_KEY_TRANSFER: handle_public_key_transfer_request,
            RequestCodes.RELOGIN: handle_relogin_request,
            RequestCodes.FILETRANSFER: handle_file_transfer_request,
            RequestCodes.VALIDCRC: handle_valid_crc_reqeust,
            RequestCodes.INVALIDCRC: handle_invalid_crc_request,
            RequestCodes.INVALIDCRCFOURTHTIME: handle_invalid_crc_fourth_time_request
        }

        response = handler_dict[req.header.code](req) # type:ignore

        if response:
            conn.sendall(response.pack())

        if req.header.code == RequestCodes.VALIDCRC or req.header.code == RequestCodes.INVALIDCRCFOURTHTIME:
            conn.close()
            break

def initialize_users_dictionary():
    clients = db.get_all_clients()

    for client in clients:
        pass

def start_server(PORT:int):
    # Todo: add check db
    db.start()

    initialize_users_dictionary()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('localhost', PORT))
            sock.listen()

            while True:
                conn, addr = sock.accept()
                t = Thread(target=wait_for_requests, args=(conn,))
                t.run()

    except Exception as e:
        print(e)
        if sock:
            sock.close()