import socket
import threading
import json
import hashlib


# Characters allowed in usernames and passwords
allowed_chars = set('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_=+')


def send_messages(connection):
    while True:
        message = input()
        data = json.dumps({'action': 'send', 'text': message})
        connection.sendall(data.encode('utf-8'))


def check_username(username):
    if len(username) > 16:
        return False
    for char in username:
        if char not in allowed_chars:
            return False
    return True


def check_password(password):
    if len(password) > 32:
        return False
    for char in password:
        if char not in allowed_chars:
            return False
    return True


def get_username(new_user):
    while True:
        username = input('Username: ')
        if not new_user or check_username(username):
            break
        print('Invalid username. Allowed characters are letters, numbers, -, _, = and +. '
              'No diacritics are allowed. It cannot be more than 16 characters long')
    return username


def get_password(new_user):
    while True:
        password = input('Password: ')
        if not new_user or check_password(password):
            break
        print('Invalid password. Allowed characters are letters, numbers, -, _, = and +. '
              'No diacritics are allowed. It cannot be more than 32 characters long')

    password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return password


HOST = '192.168.2.11'
HOST = 'localhost'
PORT = 26951


new_user = True if input('Do you have an account (y/n)? ') == 'n' else False
username = get_username(new_user)
password = get_password(new_user)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Either create a login for a user or log them in
    if new_user:
        while True:
            s.sendall(json.dumps({'action': 'register', 'username': username, 'password': password}).encode('utf-8'))
            response = json.loads(s.recv(1024))
            if response['ok']:
                break
            if response['reason'] == 1:
                print('Username is in use. Choose a different one')
                username = get_username(new_user)
        s.sendall(json.dumps({'action': 'login', 'username': username, 'password': password}).encode('utf-8'))
        s.recv(1024)
    else:
        while True:
            s.sendall(json.dumps({'action': 'login', 'username': username, 'password': password}).encode('utf-8'))
            response = json.loads(s.recv(1024))
            if response['ok']:
                break
            if response['reason'] == 1:
                print('Incorrect username. Please reenter')
                username = get_username(new_user)
            elif response['reason'] == 2:
                print('Incorrect password. Please reenter')
                password = get_password(new_user)

    sending_thread = threading.Thread(target=send_messages, args=(s,), daemon=True)
    sending_thread.start()
    while True:
        try:
            received = s.recv(1024)
            if not received:
                raise ConnectionResetError
        except ConnectionResetError:
            print('Connection closed by server')
            break
        received = json.loads(received)
        if received['action'] == 'send':
            print(f'{received["user"]}: {received["text"]}')
        elif received['action'] == 'connection':
            print(f'{received["user"]} connected')
        elif received['action'] == 'disconnection':
            print(f'{received["user"]} disconnected')
