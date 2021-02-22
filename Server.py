import socket
import threading


def manage_client(conn, iden):
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
    for conn, iden in users:
        if iden != origin:
            conn.sendall(message)


HOST = 'localhost'
PORT = 56789

users = []
threads = []

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        connection, address = s.accept()
        identity = f'{address[0]}:{address[1]}'
        print(f'Recieved connection from {identity}')
        users.append((connection, identity))
        client_thread = threading.Thread(target=manage_client, args=(connection, identity), daemon=True)
        threads.append(client_thread)
        client_thread.start()
