import socket
import threading


def manage_client(conn, addr):
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f'Received {data} from {addr[0]}:{addr[1]}')


HOST = 'localhost'
PORT = 56789

users = {}

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    connection, address = s.accept()
    print(f'Recieved connection from {address[0]}:{address[1]}')
    manage_client(connection, address)