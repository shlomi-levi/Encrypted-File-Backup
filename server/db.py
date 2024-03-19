import sqlite3

from datetime import datetime
from constants import Database
from User import User
from enum import IntEnum

sql_conn = sqlite3.connect(Database.DATABASE_NAME)

cursor = sql_conn.cursor()
sql_conn.text_factory = bytes

class KeyType(IntEnum):
    PublicKey = 0
    AESKey = 1

def get_current_time_string() -> str:
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def verify_tables_existence() -> None:
    try:
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{Database.CLIENTS_TABLE_NAME}'")
        res = cursor.fetchall()

        if not res:
            query = f"""CREATE TABLE {Database.CLIENTS_TABLE_NAME} (
                ID BLOB NOT NULL PRIMARY KEY, 
                NAME VARCHAR(255), 
                PublicKey BLOB, 
                LastSeen TEXT, 
                "AES Key" BLOB
            )"""

            sql_conn.execute(query)

        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{Database.FILES_TABLE_NAME}'")
        res = cursor.fetchall()

        if not res:
            query = f"""CREATE TABLE {Database.FILES_TABLE_NAME} (
                ID BLOB NOT NULL, 
                "File Name" VARCHAR(255), 
                "Path Name" VARCHAR(255), 
                Verified INTEGER,
                PRIMARY KEY(ID, "File Name")
            )"""

            sql_conn.execute(query)

    except Exception as e:
        print(e)
        die()
        exit()

def client_exists(uuid:bytes) -> bool:
    try:
        query = f"SELECT * from {Database.CLIENTS_TABLE_NAME} where ID=?"""
        cursor.execute(query, (uuid,))

        res = cursor.fetchall()

        if res:
            return True

        return False

    except Exception as e:
        print(e)
        die()
        exit()

# def __get_key(uuid:bytes, ktype:KeyType) -> bytes:
#     if not client_exists(uuid):
#         raise Exception("Client doesn't exist in " + Database.CLIENTS_TABLE_NAME + " table.")
#
#     if ktype == KeyType.PublicKey:
#         query = f"""SELECT PublicKey from {Database.CLIENTS_TABLE_NAME} WHERE ID=?"""
#         cursor.execute(query, (uuid,))
#
#     elif ktype == KeyType.AESKey:
#         query = f"""SELECT 'AES Key' from {Database.CLIENTS_TABLE_NAME} WHERE ID=?"""
#         cursor.execute(query, (uuid,))
#
#     res = cursor.fetchall()
#
#     return res[0]
#
# def get_public_key(uuid:bytes) -> bytes:
#     return __get_key(uuid, KeyType.PublicKey)
#
# def get_aes_key(uuid:bytes) -> bytes:
#     return __get_key(uuid, KeyType.AESKey)

def create_client(u:User) -> None:
    if client_exists(u.user_id):
        return

    try:
        query = f"""
                INSERT INTO {Database.CLIENTS_TABLE_NAME} (ID, 'Name', 'PublicKey', 'LastSeen', 'AES Key') 
                Values (?, ?, ?, ?, ?)"""

        sql_conn.execute(query, (u.user_id, u.name, u.public_key, get_current_time_string(), u.AES_key))

        sql_conn.commit()

    except Exception as e:
        print(e)
        die()
        exit()

def add_file(client_id:bytes, file_name:str, file_path:str, verified:bool) -> None:
    _verified = 1 if verified else 0

    try:
        query = f"""SELECT * FROM {Database.FILES_TABLE_NAME} WHERE ID=? AND "File Name"=?"""
        cursor.execute(query, (client_id, file_name))

        if cursor.fetchall():
            query = f"""DELETE FROM {Database.FILES_TABLE_NAME} WHERE ID=? AND "File Name"=?"""
            sql_conn.execute(query, (client_id, file_name))
            sql_conn.commit()

        query = f"""INSERT INTO {Database.FILES_TABLE_NAME} (ID, "File Name", "Path Name", Verified)
                VALUES (?, ?, ?, ?)"""

        sql_conn.execute(query, (client_id, file_name, file_path, _verified))
        sql_conn.commit()

    except Exception as e:
        print(e)
        sql_conn.close()
        exit()

def get_all_clients() -> list[User]:
    ret = []

    query = f"""SELECT Name, "ID", "PublicKey", "AES Key" FROM {Database.CLIENTS_TABLE_NAME}"""
    cursor.execute(query)
    users = cursor.fetchall()

    for u in users:
        _name = u[0].decode()
        ret.append(User(_name, u[1], u[2], u[3]))

    return ret

def update_last_seen(u:User) -> None:
    if not client_exists(u.user_id):
        return create_client(u)

    try:
        query = f"UPDATE {Database.CLIENTS_TABLE_NAME} SET LastSeen=? WHERE ID=?"
        sql_conn.execute(query, (get_current_time_string(), u.user_id))
        sql_conn.commit()

    except Exception as e:
        print(e)
        die()
        exit()

def die() -> None:
    sql_conn.close()

def start() -> None:
    verify_tables_existence()