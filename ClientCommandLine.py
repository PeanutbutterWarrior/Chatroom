import socket
import threading
import ClientCommon as cc

HOST = 'localhost'
PORT = 26950


def listen():
    while True:
        try:
            data = cc.receive(s)
        except ConnectionResetError:
            print('Disconnected by server')
            break
        print(cc.message_format_dispatch[data['action']](data))


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    rsa_key = cc.get_rsa_key(s)
    listening_thread = threading.Thread(target=listen, daemon=True)

    while True:
        action = input('Do you want to (1) log in or (2) register a new account? ')
        username = input('What is your username? ')
        password = input('What is your password? ')
        password = cc.encrypt_password(password, rsa_key)
        if action == '1':
            cc.send(s, action='login', username=username, password=password)
            response = cc.receive(s)
            if response['ok']:
                break
            print(response['reason'])
        elif action == '2':
            cc.send(s, action='register', username=username, password=password)
            response = cc.receive(s)
            if response['ok']:
                cc.send(s, action='login', username=username, password=password)
                cc.receive(s)
                break
            print(response['reason'])

    listening_thread.start()

    while True:
        message = input()
        if message:
            if message[0] == '/':
                command, *args = message.split()
                if command == '/password':
                    args = (cc.encrypt_password(args[0], rsa_key), )
                cc.send(s, action='command', command=command[1:], args=args)
            else:
                cc.send(s, action='message', text=message)
