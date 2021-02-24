import socket
import threading
import json
import ClientCommon as cc

HOST = 'localhost'
PORT = 26951


def send(connection):
    while True:
        message = input()
        cc.send_message(message, connection)


def get_username(new_usr):
    while True:
        usr = input('Username: ')
        if (not new_usr) or (failure := cc.check_username(usr)) is True:
            break
        else:
            print(failure)
    return usr


def get_password(new_usr):
    while True:
        pswd = input('Password: ')
        if (not new_usr) or (failure := cc.check_password(pswd)) is True:
            break
        else:
            print(failure)
    return pswd


new_user = True if input('Do you have an account (y/n)? ') == 'n' else False
username = get_username(new_user)
password = get_password(new_user)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Either create a login for a user or log them in
    if new_user:
        while True:
            response = cc.register(username, password, s)
            if response is True:
                break
            print(response['reason'])
            username = get_username(new_user)
        cc.login(username, password, s)
    else:
        while True:
            response = cc.login(username, password, s)
            if response is True:
                break
            else:
                print(response)
                username = get_username(new_user)
                password = get_password(new_user)

    sending_thread = threading.Thread(target=send, args=(s,), daemon=True)
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
