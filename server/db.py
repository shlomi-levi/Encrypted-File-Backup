import sqlite3
from constants import Database

conn = sqlite3.connect('defensive.db')
conn.text_factory = bytes

def verify_tables_existence():
    cursor = conn.cursor()

    try:
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{Database.CLIENTS_TABLE_NAME}'")
        res = cursor.fetchall()

        if not res:
            conn.execute(f"""CREATE TABLE {Database.CLIENTS_TABLE_NAME}(ID VARCHAR(16) NOT NULL PRIMARY KEY, NAME VARCHAR(255), PublicKey VARCHAR(160), LastSeen TEXT, "AES" Key" VARCHAR(32)""")

        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{Database.FILES_TABLE_NAME}'")
        res = cursor.fetchall()

        if not res:
            conn.execute(f"""CREATE TABLE {Database.FILES_TABLE_NAME}(ID VARCHAR(16) NOT NULL PRIMARY KEY, "File Name" VARCHAR(255) PRIMARY KEY, "Path Name" VARCHAR(255), Verified INTEGER""")

    except Exception as e:
        print(e)
        die()
        exit(1)

def die():
    conn.close()

def start():
    verify_tables_existence()




