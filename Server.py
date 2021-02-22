import socket
import threading


def manage_client(conn, addr):
    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                print(f'Received {data} from {addr[0]}:{addr[1]}')
            except ConnectionResetError:
                print(f'{addr[0]}:{addr[1]} disconnected')
                break


HOST = 'localhost'
PORT = 56789

users = {}
threads = []

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    while True:
        connection, address = s.accept()
        print(f'Recieved connection from {address[0]}:{address[1]}')
        client_thread = threading.Thread(target=manage_client, args=(connection, address), daemon=True)
        threads.append(client_thread)
        client_thread.start()
