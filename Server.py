import socket
import threading


def manage_client(conn, iden):
    username = conn.recv(1024).decode('utf-8')
    users[iden]['username'] = username
    users[iden]['ready'] = True
    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                print(f'Received {data} from {iden}')
                disseminate_message(iden, data)
            except ConnectionResetError:
                print(f'{iden} disconnected')
                break


def disseminate_message(origin, message):
    to_send = f'{users[origin]["username"]}: {message.decode("utf-8")}'.encode('utf-8')
    for iden, data in users.items():
        if iden != origin and data['ready']:
            data['connection'].sendall(to_send)


HOST = 'localhost'
PORT = 56789

users = {}
threads = []

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        connection, address = s.accept()
        identity = f'{address[0]}:{address[1]}'
        print(f'Recieved connection from {identity}')
        client_thread = threading.Thread(target=manage_client, args=(connection, identity), daemon=True)
        users[identity] = {'connection': connection, 'thread': client_thread, 'ready': False}
        threads.append(client_thread)
        client_thread.start()
