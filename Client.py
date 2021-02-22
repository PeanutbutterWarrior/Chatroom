import socket
import time
import threading


def send_messages(connection):
    while True:
        message = input()
        connection.sendall(message.encode('utf-8'))


HOST = 'localhost'
PORT = 56789

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    sending_thread = threading.Thread(target=send_messages, args=(s,), daemon=True)
    sending_thread.start()
    while True:
        try:
            data = s.recv(1024)
        except ConnectionResetError:
            print('Connection closed by server')
            break
        print(data.decode('utf-8'))
