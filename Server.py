import socket
import threading

HOST = 'localhost'
PORT = 56789


def manage_client(conn, iden):
    username = conn.recv(1024).decode('utf-8')
    users[iden]['name'] = username
    print(f'{iden} is named {username}')
    users[iden]['ready'] = True
    disseminate_message(iden, f'{users[iden]["name"]} connected'.encode('utf-8'), prefix_username=False)
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
                disseminate_message(
                                    iden,
                                    f'{users[iden]["name"]} disconnected'.encode('utf-8'),
                                    prefix_username=False
                                    )
                del users[iden]
                break
            except BlockingIOError:
                pass


def disseminate_message(origin, message, prefix_username=True):
    if prefix_username:
        to_send = f'{users[origin]["name"]}: {message.decode("utf-8")}'.encode('utf-8')
    else:
        to_send = message
    for iden, data in users.items():
        if iden != origin and data['ready']:
            data['connection'].sendall(to_send)


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
            identity = f'{address[0]}:{address[1]}'
            print(f'Recieved connection from {identity}')
            client_thread = threading.Thread(target=manage_client, args=(connection, identity), daemon=True)
            users[identity] = {'connection': connection, 'thread': client_thread, 'ready': False}
            threads.append(client_thread)
            client_thread.start()


users = {}
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
