import socket
import threading
import json
import csv

HOST = '0.0.0.0'
PORT = 56789
AUTHENTICATION_PORT = 56788


def manage_client(conn, identity):
    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    raise ConnectionResetError
            except ConnectionResetError:
                if users[identity]['logged_in']:
                    print(f'{users[identity]["username"]} disconnected')
                    disseminate_message(identity, {'action': 'disconnection',
                                                   'user': users[identity]['username']})
                    del users[identity]
                    break
                print(f'{identity} disconnected')
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

                    elif logins[data['username']]['password'] != data['password']:
                        conn.sendall(json.dumps({'ok': False, 'reason': 2}).encode('utf-8'))

                    else:
                        conn.sendall(json.dumps({'ok': True}).encode('utf-8'))
                        users[identity]['logged_in'] = True
                        users[identity]['ready'] = True
                        users[identity]['username'] = data['username']
                        print(f'{identity} logged in as {data["username"]}')
                        disseminate_message(identity, {'action': 'connection',
                                                       'user': users[identity]['username']})

                elif data['action'] == 'register':
                    if data['username'] in logins:
                        conn.sendall(json.dumps({'ok': False, 'reason': 1}).encode('utf-8'))
                    else:
                        conn.sendall(json.dumps({'ok': True}).encode('utf-8'))
                        print(f'{identity} registers as {data["username"]}')
                        logins[data['username']] = {'password': data['password'], 'admin': False}
                        logins_queue.append((data['username'], data['password'], False))

                elif data['action'] == 'listen':
                    users[identity]['ready'] = True
                    print(f'{identity} is now listening')

                else:
                    print(f'! Bad action {data} from {identity}')
    threads.remove(threading.current_thread())


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
            identity = f'{address[0]}:{address[1]}'
            print(f'Recieved connection from {identity}')
            client_thread = threading.Thread(target=manage_client,
                                             args=(connection, identity),
                                             daemon=True,
                                             name=identity+'-client'
                                             )
            users[identity] = {'connection': connection, 'thread': client_thread, 'ready': False, 'logged_in': False}
            threads.add(client_thread)
            client_thread.start()
    threads.remove(threading.current_thread())


def write_files():
    login_file = open('users.csv', 'a', newline='')
    writer = csv.writer(login_file)

    while running:
        if len(logins_queue) > 0:
            login = logins_queue.pop(-1)
            writer.writerow((login[0], login[1], str(login[2])))
            print(f'Written {login[0]} to disk')
            login_file.flush()

    login_file.close()
    threads.remove(threading.current_thread())


# Commands


def userinfo(reference, identity):
    for ip, user in users.items():
        if reference == 'name' and user['username'] == identity:
            print(ip, user)
            break
        elif reference == 'id' and ip == identity:
            print(ip, user)
            break
    else:
        print('No user found')


def kick(reference, identity, mask='none'):
    for ip, user in users.items():
        if reference == 'name' and user['username'] == identity:
            break
        elif reference == 'id' and ip == identity:
            break
    else:
        print('No user found')
        return

    user['connection'].close()
    if mask == 'none':
        disseminate_message(ip, {'action': 'kick', 'user': user})
    elif mask == 'disconnect':
        disseminate_message(ip, {'action': 'kick', 'user': user})


def debug():
    print(users)
    print(logins)
    print(logins_queue)
    print(threads)
    print(running)


dispatch = {'userinfo': userinfo, 'kick': kick, 'debug': debug}

if __name__ == '__main__':
    users = {}
    logins = {}
    logins_queue = []
    threads = set()
    running = True

    # Read in logins
    with open('users.csv', 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            logins[row[0]] = {'password': row[1], 'admin': bool(row[2])}

    # Accepts new connections
    accepting_thread = threading.Thread(target=accept_connections, name='accepting')
    threads.add(accepting_thread)

    # Writes data to files from queues
    file_writing_thread = threading.Thread(target=write_files, name='file_writing')
    threads.add(file_writing_thread)

    file_writing_thread.start()
    accepting_thread.start()

    while running:
        command, *args = input().split()
        if command == 'exit':
            running = False
        else:
            try:
                dispatch[command](*args)
            except KeyError:
                print('Unknown command')
            except TypeError:
                print('Bad arguments for command')
            except Exception as error:
                print('Unknown error')
                print(error)

    accepting_thread.join()
    file_writing_thread.join()
