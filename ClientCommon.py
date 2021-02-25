import json
import hashlib
import rsa

# Characters allowed in usernames and passwords
allowed_chars = set('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_=+')


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


def send_message(data, connection):
    message = json.dumps({'action': 'send', 'text': data})
    connection.sendall(message.encode('utf-8'))


def login(username, password, connection):
    password = rsa.encrypt(password.encode('utf-8'), get_key(connection)).hex()
    connection.sendall(json.dumps({'action': 'login',
                                   'username': username,
                                   'password': password}).encode('utf-8'))
    response = json.loads(connection.recv(1024))
    if response['ok']:
        return True
    else:
        return response['reason']


def register(username, password, connection):
    password = rsa.encrypt(password.encode('utf-8'), get_key(connection)).hex()

    connection.sendall(json.dumps({'action': 'register', 'username': username, 'password': password}).encode('utf-8'))
    response = json.loads(connection.recv(1024))

    if response['ok']:
        return True
    else:
        return response['reason']


def listen(connection):
    connection.sendall(json.dumps({'action': 'listen'}).encode('utf-8'))


def get_key(connection):
    connection.sendall(json.dumps({'action': 'get_key'}).encode('utf-8'))
    data = json.loads(connection.recv(1024))
    return rsa.PublicKey(n=data['n'], e=data['e'])
