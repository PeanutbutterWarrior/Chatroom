import socket
import threading
import json
import csv
import inspect

HOST = '0.0.0.0'
PORT = 26951


def manage_client(conn, identity):
    user = users[identity]
    with conn:
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    raise ConnectionResetError
            except BlockingIOError:
                continue
            except (ConnectionResetError, OSError):
                if user['logged_in']:
                    print(f'{user["username"]} disconnected')
                    disseminate_message(identity, {'action': 'disconnection', 'user': user['username']})
                    del users[identity]
                    break
                print(f'{identity} disconnected')
                break

            data = json.loads(data)
            if data['action'] == 'send':
                if user['logged_in']:
                    print(f'{user["username"]}: {data["text"]}')
                    disseminate_message(identity, {'action': 'send',
                                                   'text': data['text'],
                                                   'user': user['username']})
            elif data['action'] == 'command':
                cmd = data['command']
                args = data['args']
                if user['admin']:
                    dispatch_table = admin_command_dispatch
                else:
                    dispatch_table = standard_command_dispatch

                try:
                    conn.sendall(encode(action='command-response', text=dispatch_table[cmd](*args)))
                except KeyError:
                    conn.sendall(encode(action='command-response', text='Unknown command'))
                except TypeError:
                    conn.sendall(encode(action='command-response', text='Bad aruments for command'))

            elif data['action'] == 'login':
                if data['username'] not in logins:
                    conn.sendall(encode(ok=False, reason='There is no account with that name'))
                elif logins[data['username']]['password'] != data['password']:
                    conn.sendall(encode(ok=False, reason='The password is incorrect'))
                elif user['logged_in']:
                    conn.sendall(encode(ok=False, reason='You are already logged in'))
                else:
                    conn.sendall(encode(ok=True))
                    user['logged_in'] = True
                    user['ready'] = True
                    user['username'] = data['username']
                    user['admin'] = logins[data['username']]['admin']
                    print(f'{identity} logged in as {data["username"]}')
                    disseminate_message(identity, {'action': 'connection',
                                                   'user': user['username']})

            elif data['action'] == 'register':
                if data['username'] in logins:
                    conn.sendall(encode(ok=False, reason='That username is already in use'))
                else:
                    conn.sendall(encode(ok=True))
                    print(f'{identity} registers as {data["username"]}')
                    logins[data['username']] = {'password': data['password'], 'admin': False}
                    logins_queue.append((data['username'], data['password'], False))

            elif data['action'] == 'listen':
                user['ready'] = True
                print(f'{identity} is now listening')

            elif data['action'] == 'logout':
                disseminate_message(identity, {'action': 'disconnection', 'user': user['username']})
                user['logged_in'] = False
                user['ready'] = False
                del user['username'], user['admin']

            else:
                print(f'! Bad action {data} from {identity}')
    threads.remove(threading.current_thread())


def disseminate_message(origin, data):
    data = json.dumps(data).encode('utf-8')
    for identity, user_data in users.items():
        if identity != origin and user_data['ready']:
            try:
                user_data['connection'].sendall(data)
            except OSError:
                pass


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


def encode(**kwargs):
    return json.dumps(kwargs).encode('utf-8')


# Commands


def userinfo(reference, identity):
    """
    Gets information on a user
    Admin only
    Usage: /userinfo reference_type identity
    reference_type: either 'ip' or 'name'
    identity: the identity of the user, either their name or ip:port
    """
    for ip, user in users.items():
        if reference == 'name' and user['username'] == identity:
            return f'ip: {ip}, data: {user}'
        elif reference == 'id' and ip == identity:
            return f'ip: {ip}, data: {user}'
    return 'No user found'


def kick(reference, identity, mask='none'):
    """
    Kicks a user from the server. Does not stop them reconnecting
    Admin only
    Usage: /kick reference identity [mask='none']
    reference: either 'ip' or 'name'
    identity: the identity of the user, either their name or ip:port
    mask: 'none', 'disconnect' or 'hidden'. Hides or changes the kicking
    """
    for ip, user in users.items():
        if reference == 'name' and user['username'] == identity:
            break
        elif reference == 'id' and ip == identity:
            break
    else:
        return 'No user found'

    if mask == 'none':
        disseminate_message(ip, {'action': 'kick', 'user': user})
    elif mask == 'disconnect':
        disseminate_message(ip, {'action': 'disconnect', 'user': user})
    elif mask == 'hidden':
        pass
    else:
        return 'Bad mask argument'
    user['connection'].close()
    print(f'{user["username"]} was kicked')
    return f'{user["username"]} was kicked'


def debug():
    """
    Gives debug information. Only prints to the server console
    Usage: /debug
    """
    print(users)
    print(logins)
    print(logins_queue)
    print(threads)
    print(running)


def promote(reference, identity):
    """
    Promotes a user to admin#
    Admin only
    Usage: /promote reference identity
    reference: either 'ip' or 'name'
    identity: the identity of the user, either their name or ip:port
    """
    for ip, user in users.items():
        if reference == 'name' and user['username'] == identity:
            break
        elif reference == 'id' and ip == identity:
            break
    else:
        return 'No user found'
    if user['admin']:
        return 'That user is already an admin'
    user['admin'] = True
    print(f'{user["username"]} was promoted')
    disseminate_message(None, {'action': 'promotion', 'user': user['username']})
    return f'{user["username"]} was promoted'


def help_command(command_name):
    """
    Gives information on the usage of a command
    Usage: /help command_name
    command_name: The name of the command
    """
    try:
        return inspect.getdoc(admin_command_dispatch[command_name])
    except IndexError:
        return 'No command with that name'


standard_command_dispatch = {'debug': debug, 'help': help_command}
admin_command_dispatch = {'userinfo': userinfo, 'kick': kick, 'promote': promote}
# Admins have access to all commands, including standard ones
admin_command_dispatch.update(standard_command_dispatch)

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
            logins[row[0]] = {'password': row[1], 'admin': row[2] == 'True'}

    # Accepts new connections
    accepting_thread = threading.Thread(target=accept_connections, name='accepting')
    threads.add(accepting_thread)

    # Writes data to files from queues
    file_writing_thread = threading.Thread(target=write_files, name='file_writing')
    threads.add(file_writing_thread)

    file_writing_thread.start()
    accepting_thread.start()

    while running:
        command, *arguments = input().split()
        if command == 'exit':
            running = False
        else:
            try:
                print(admin_command_dispatch[command](*arguments))
            except KeyError:
                print('Unknown command')
            except TypeError:
                print('Bad arguments for command')
            except Exception as error:
                print('Unknown error')
                print(error)

    accepting_thread.join()
    file_writing_thread.join()
