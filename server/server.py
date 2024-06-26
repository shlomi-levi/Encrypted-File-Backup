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

users_map:dict[uuid, User] = {}

def get_file_directory(client_id):
    return f"{client_id.hex()}"

def get_file_path(user_id:bytes, file_name:str) -> str:
    return get_file_directory(user_id) + "\\" + basename(file_name)

def handle_registration_request(req:Requests.Registration) -> Responses.Response:
    user_uuid = uuid.uuid4().bytes

    while user_uuid in users_map:
        user_uuid = uuid.uuid4().bytes.decode()

    users_map[user_uuid] = User(req.name, user_uuid, b'', b'')

    res = Responses.RegisterationSuccess(user_uuid)

    print(f"The client {req.name} (UUID: {user_uuid.hex()}) has registered successfully.")

    return res

def handle_public_key_transfer_request(req:Requests.PublicKeyTransfer) -> Responses.Response:
    if req.header.client_id not in users_map:
        return Responses.GeneralServerError()

    u:User = users_map[req.header.client_id]
    u.public_key = req.public_key

    aes_key = get_random_bytes(FieldsSizes.AES_KEY)
    u.AES_key = aes_key

    encrypted_aes_key:bytes = PKCS1_OAEP.new(RSA.importKey(req.public_key)).encrypt(aes_key)

    db.create_client(u)

    print(f"Public key recieved from {u.name} ({u.user_id.hex()}) and an encrypted AES key was sent back.")

    return Responses.PublicKeyRecieved(req.header.client_id, encrypted_aes_key)

def handle_relogin_request(req:Requests.Relogin) -> Responses.Response:
    cid = req.header.client_id
    _cid_hex = cid.hex()

    if cid not in users_map or not users_map[cid].public_key:
        print(f"Relogin declined for {req.client_name} since the server doesn't recognize this uuid ({_cid_hex})")
        return Responses.DeclineReLogin(cid)

    user = users_map[cid]

    if req.client_name != user.name:
        print(f"Relogin failed for the user (UUID: {_cid_hex}) because the name he provided wasn't the correct name")
        return Responses.DeclineReLogin(cid)

    rsa_encrypter = PKCS1_OAEP.new(RSA.importKey(user.public_key))
    encrypted_aes_key: bytes = rsa_encrypter.encrypt(user.AES_key)

    print(f"Successfuly relogin for the client {req.client_name} (UUID: {_cid_hex})")

    db.update_last_seen(user)

    return Responses.AllowRelogin(cid, encrypted_aes_key)

def handle_file_transfer_request(req:Requests.FileTransfer) -> Responses.Response:
    if req.header.client_id not in users_map:
        return Responses.GeneralServerError()

    directory = get_file_directory(req.header.client_id)

    if not os.path.exists(directory):
        os.makedirs(directory)

    file_path = get_file_path(req.header.client_id, req.file_name)

    user = users_map[req.header.client_id]
    cipher = AES.new(user.AES_key, AES.MODE_CBC, iv=b'\x00' * 16)

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

        return Responses.GeneralServerError()

    if f:
        f.close()

def handle_valid_crc_reqeust(req:Requests.ValidCRC) -> Responses.Response:
    cname = users_map[req.header.client_id].name
    print(f"A file was recieved from the client {cname} (UUID: {req.header.client_id.hex()}) and was verified successfully")
    db.add_file(req.header.client_id, req.file_name, get_file_path(req.header.client_id, req.file_name), True)
    return Responses.MessageRecieved(req.header.client_id)

def handle_invalid_crc_request(req:Requests.InvalidCRC) -> Responses.Response:
    return None # type:ignore

def handle_invalid_crc_fourth_time_request(req:Requests.InvalidCRCFourthTime) -> Responses.Response:
    cname = users_map[req.header.client_id].name
    print(f"A file was recieved from the client {cname} (UUID: {req.header.client_id.hex()}) , but the verification failed")
    db.add_file(req.header.client_id, req.file_name, get_file_path(req.header.client_id, req.file_name), False)
    return Responses.MessageRecieved(req.header.client_id)

def wait_for_requests(conn):
    while True:
        req:Requests.Request = Requests.parse_request(conn)

        if not req:
            conn.sendall(Responses.GeneralServerError().pack())
            continue

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
        users_map[client.user_id] = client

    print(f"Loaded {len(clients)} users from database")

def start_server(PORT:int):
    print("Loading users from database")

    db.start()

    initialize_users_dictionary()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(('localhost', PORT))
            sock.listen()

            print("Server has started on port " + str(PORT))
            
            while True:
                conn, addr = sock.accept()
                print("Server has accepted a connection")
                t = Thread(target=wait_for_requests, args=(conn,))
                t.run()

    except Exception as e:
        print(e)
        if sock:
            sock.close()