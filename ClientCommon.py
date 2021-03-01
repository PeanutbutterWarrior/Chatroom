import json
import rsa
import socket

# Characters allowed in usernames and passwords
allowed_chars = set('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_=+')
HOST = 'localhost'
PORT = 26950
RECEIVE_SIZE = 1024


def check_username(username):
    if len(username) > 16:
        return 'Username cannot be more than 16 characters in length'
    for char in username:
        if char not in allowed_chars:
            return 'Username must be made of letters, numbers,  -, _ , = and +. No diacritics are allowed.'
    return True


def check_password(password):
    if len(password) > 32:
        return 'Password cannot be more than 32 characters in length'
    for char in password:
        if char not in allowed_chars:
            return 'Password must be made of letters, numbers,  -, _ , = and +. No diacritics are allowed.'
    return True


def get_rsa_key(connection):
    send(connection, action='get_key')
    key = receive(connection)
    return rsa.PublicKey(n=key['n'], e=key['e'])


def encrypt_password(password, connection):
    return rsa.encrypt(password.encode('utf-8'), get_rsa_key(connection)).hex()


def receive(connection):
    message_size = int(connection.recv(5))
    message_chunks = []
    bytes_received = 0
    while bytes_received < message_size:
        data = connection.recv(RECEIVE_SIZE)
        if not data:
            raise ConnectionResetError
        bytes_received += len(data)
        message_chunks.append(data)
    return json.loads(b''.join(message_chunks))


def send(connection, **kwargs):
    message = json.dumps(kwargs).encode('utf-8')
    message_size = len(message)
    connection.send(str(message_size).zfill(5).encode('utf-8'))
    bytes_sent = 0
    while bytes_sent < message_size:
        bytes_sent += connection.send(message[bytes_sent:])
