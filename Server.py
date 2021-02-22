import socket
import threading
import json

HOST = 'localhost'
PORT = 56789
AUTHENTICATION_PORT = 56788


def manage_client(conn, identity):
    with conn:
        while True:
            try:
                data = conn.recv(1024)
            except ConnectionResetError:
                if users[identity]['logged_in']:
                    print(f'{identity} disconnected')
                    disseminate_message(identity, {'action': 'disconnection',
                                                   'user': users[identity]['username']})
                    del users[identity]
                    break
            except BlockingIOError:
                pass

            else:
                if not data:
                    break
                data = json.loads(data)
                if data['action'] == 'send':
                    if users[identity]['logged_in']:
                        print(f'{users[identity]["username"]}: {data["text"]}')
                        disseminate_message(identity, {'action': 'send',
                                                       'text': data['text'],
                                                       'user': users[identity]['username']})
                elif data['action'] == 'login':
                    if data['username'] not in logins:
                        conn.sendall(json.dumps({'ok': False, 'reason': 1}).encode('utf-8'))

                    elif logins[data['username']] != data['password']:
                        conn.sendall(json.dumps({'ok': False, 'reason': 2}).encode('utf-8'))

                    else:
                        conn.sendall(json.dumps({'ok': True}).encode('utf-8'))
                        users[identity]['logged_in'] = True
                        users[identity]['ready'] = True
                        users[identity]['username'] = data['username']
                        disseminate_message(identity, {'action': 'connection',
                                                       'user': users[identity]['username']})

                elif data['action'] == 'register':
                    if data['username'] in logins:
                        conn.sendall(json.dumps({'ok': False, 'reason': 1}).encode('utf-8'))
                    else:
                        conn.sendall(json.dumps({'ok': True}).encode('utf-8'))
                        logins[data['username']] = data['password']

                elif data['action'] == 'listen':
                    users[identity]['ready'] = True

                else:
                    print(f'! Bad action {data} from {identity}')


def disseminate_message(origin, data):
    data = json.dumps(data).encode('utf-8')
    for identity, user_data in users.items():
        if identity != origin and user_data['ready']:
            user_data['connection'].sendall(data)


def accept_connections():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.setblocking(False)
        s.listen()
        while running:
            try:
                connection, address = s.accept()
            except BlockingIOError:
                continue
            identitytity = f'{address[0]}:{address[1]}'
            print(f'Recieved connection from {identitytity}')
            client_thread = threading.Thread(target=manage_client, args=(connection, identitytity), daemon=True)
            users[identitytity] = {'connection': connection, 'thread': client_thread, 'ready': False, 'logged_in': False}
            threads.append(client_thread)
            client_thread.start()


users = {}
logins = {}
threads = []
running = True

accepting_thread = threading.Thread(target=accept_connections)
threads.append(accepting_thread)
accepting_thread.start()

while running:
    command = input()
    if command == 'exit':
        running = False

accepting_thread.join()
