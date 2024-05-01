# Encrypted File Backup
[![Encrypted File Backup](https://img.shields.io/badge/Encrypted_File_Backup-Python%20%7C%20C++-blue)](https://github.com/shlomi-levi/Encrypted-File-Backup)

This is a project that was written as a part of the course 'Defensive Systems Programming' in The Open University,

In essence, the client (which is written in C++), and the server (written in Python), exchange encryption keys,
then the client sends an encrypted file to the server, which decrypts the file and stores it in a special folder reserved for that client. Information about the transfers is saved using SQLite.

In order for this program to work, the following libraries are needed:

Python Libraries: PyCryptoDome, sqlite

C++ Libraries: Boost, Crypto++

---
