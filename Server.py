import hashlib
import inspect
import json
import rsa
import secrets
import socket
import sqlite3
import threading
import select
import queue

HOST = '0.0.0.0'
PORT = 26950

MAX_CLIENT_THREADS = 8  # Will spawn this many ClientManagers at most each with a thread, plus two extra threads


class ClientManager:
    def __init__(self):
        self.clients = []
        self.thread = None
        self.running = False
        self.pending_messages = queue.SimpleQueue()

    def run(self):
        self.pending_messages = queue.SimpleQueue()
        while running:
            if self.clients:
                ready_to_read, *_ = select.select(self.clients, [], [], 1)
                for client in ready_to_read:
                    try:
                        data = client.receive()
                    except (ConnectionResetError, OSError):
                        client.close()
                        self.clients.remove(client)
                        print(f'{str(client)} disconnected')
                    else:
                        client.dispatch[data['action']](data)

            while not self.pending_messages.empty():
                try:
                    message, origin = self.pending_messages.get(block=False)
                except queue.Empty:
                    break
                for client in self.clients:
                    if client != origin:
                        client.send(message=message, plain_send=True)
        for client in self.clients:
            client.close()

    def add_client(self, client):
        self.clients.append(client)


class Client:
    db = sqlite3.connect('users.db', check_same_thread=False)

    def __init__(self, connection, identity):
        self.connection = connection
        self.identity = identity
        self.name = None
        self.cursor = self.db.cursor()
        self.logged_in = False
        self.receiving = False
        self.admin = False
        self.dispatch = {'message': self.message, 'command': self.command, 'get_key': self.get_key,
                         'listen': self.listen, 'logout': self.logout, 'login': self.login, 'register': self.register}

    def send(self, force_send=False, plain_send=False, **kwargs):
        if plain_send:
            message = kwargs['message']
        else:
            message = json.dumps(kwargs).encode('utf-8')

        if self.receiving or force_send:
            message_size = len(message)
            self.connection.send(str(message_size).zfill(5).encode('utf-8'))
            bytes_sent = 0
            while bytes_sent < message_size:
                bytes_sent += self.connection.send(message[bytes_sent:])

    def receive(self):
        message_size = self.connection.recv(5)
        if not message_size:
            raise ConnectionResetError
        message_size = int(message_size)
        message_chunks = []
        bytes_received = 0
        while bytes_received < message_size:
            data = self.connection.recv(1024)
            if not data:
                raise ConnectionResetError
            bytes_received += len(data)
            message_chunks.append(data)
        return json.loads(b''.join(message_chunks))

    def close(self):
        self.connection.close()
        self.cursor.close()

    # Message actions

    def message(self, data):
        if self.logged_in:
            disseminate_message(self, action='send', text=data['text'], user=str(self))

    def command(self, data):
        if self.admin:
            dispatch = admin_command_dispatch
        else:
            dispatch = standard_command_dispatch

        try:
            self.send(action='command-response', text=dispatch[data['command']](*data['args']))
            print(f'{str(self)} ran command {data["command"]} with args {data["args"]}')
        except KeyError:
            self.send(action='command-response', text='Unknown command')
        except TypeError:
            self.send(action='command-response', text='Bad arguments for command')

    def get_key(self, data):
        self.send(action='key', n=pub_key.n, e=pub_key.e, force_send=True)

    def listen(self, data):
        self.receiving = True
        print(f'{str(self)} is now listening')

    def logout(self, data):
        disseminate_message(self, action='disconnection', user=str(self))
        self.logged_in = False
        self.receiving = False
        self.admin = False
        self.name = None

    def login(self, data):
        username = data['username']
        if self.cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone() is None:
            self.send(ok=False, reason='There is no account with that name', force_send=True)
            return

        password = self.hash_password(data['password'])
        self.cursor.execute('SELECT salt FROM salts WHERE username = ?', (username,))
        salt = self.cursor.fetchone()[0]
        password.update(bytes.fromhex(salt))
        password = password.hexdigest()
        if self.cursor.execute("SELECT password FROM users WHERE username = ?", (username,)).fetchone()[0] != password:
            self.send(ok=False, reason='The password is incorrect', force_send=True)
        elif self.logged_in:
            self.send(ok=False, reason='You are already logged in', force_send=True)
        else:
            self.send(ok=True, force_send=True)
            self.logged_in = True
            self.receiving = True
            self.name = username
            self.admin = bool(self.cursor.execute("SELECT admin FROM users WHERE username = ?", (username,)).fetchone()[0])
            print(f'{self.identity} logged in as {username}')
            disseminate_message(self, action='connection', user=str(self))

    def register(self, data):
        username = data['username']

        if self.cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone():
            self.send(ok=False, reason='That username is already in use', force_send=True)
        else:
            password = self.hash_password(data['password'])
            salt = secrets.token_hex(32)
            password.update(bytes.fromhex(salt))
            password = password.hexdigest()
            self.send(ok=True, force_send=True)
            print(f'New user {username}')
            new_logins_queue.append((username, password, 0))
            new_salts_queue.append((username, salt))

    @staticmethod
    def hash_password(password):
        password = bytes.fromhex(password)
        password = rsa.decrypt(password, priv_key)
        return hashlib.sha256(password)

    # Makes Clients work with select.select
    def fileno(self):
        return self.connection.fileno()

    def __eq__(self, other):
        if type(other) == str:
            return self.identity == other or self.name == other
        elif type(other) == Client:
            return self.identity == other.identity
        return False

    def __str__(self):
        if self.logged_in:
            return self.name
        else:
            return self.identity

    def __del__(self):
        self.connection.close()
        self.cursor.close()


def disseminate_message(origin, **kwargs):
    message = json.dumps(kwargs).encode('utf-8')
    for client_manager in client_managers:
        client_manager.pending_messages.put((message, origin), block=False)


def accept_connections():
    client_manager_index = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.setblocking(False)
        s.listen()
        while running:
            try:
                conn, address = s.accept()
            except BlockingIOError:
                continue

            identity = f'{address[0]}:{address[1]}'
            print(f'Received connection from {identity}')
            client = Client(conn, identity)

            client_managers[client_manager_index].add_client(client)
            if not client_managers[client_manager_index].running:
                client_managers[client_manager_index].thread.start()

            client_manager_index += 1
            if client_manager_index >= MAX_CLIENT_THREADS:
                client_manager_index = 0


def write_files():
    db = sqlite3.connect('users.db')
    cursor = db.cursor()
    while running:
        if len(new_logins_queue) > 0:
            cursor.executemany('INSERT INTO users VALUES (?, ?, ?)', new_logins_queue)
            print(f'Written {len(new_logins_queue)} new users to disk')
            db.commit()
            new_logins_queue.clear()
        if len(new_salts_queue) > 0:
            cursor.executemany('INSERT INTO salts VALUES (?, ?)', new_salts_queue)
            print(f'Written {len(new_salts_queue)} new salts to disk')
            db.commit()
            new_salts_queue.clear()
    db.commit()
    db.close()


# Commands


def userinfo(identity):
    """
    Gets information on a user
    Admin only
    Usage: /userinfo identity
    identity: the identity of the user, either their name or ip:port
    """
    for client_manager in client_managers:
        for client in client_manager.clients:
            if client == identity:
                return f'Name: {client.name}, Identity: {client.identity}, logged in: {client.logged_in}, ' \
                       f'receiving: {client.receiving}, admin: {client.admin}'
    return 'No user found'


def kick(identity, mask='none'):
    """
    Kicks a user from the server. Does not stop them reconnecting
    Admin only
    Usage: /kick identity [mask='none']
    identity: the identity of the user, either their name or ip:port
    mask: 'none', 'disconnect' or 'hidden'. Hides or changes the kicking
    """
    for client_manager in client_managers:
        for client in client_manager.clients:
            if client == identity:
                if mask == 'none':
                    disseminate_message(identity, action='kick', user=str(client))
                elif mask == 'disconnect':
                    disseminate_message(identity,  action='disconnect', user=str(client))
                elif mask == 'hidden':
                    pass
                else:
                    raise TypeError  # Gets caught at calling of command
                client.send(action='send', text='You have been kicked', user='[Server]')
                print(f'{str(client)} was kicked')
                client.connection.close()
                return f'{str(client)} was kicked'
    return 'No user found'


def promote(identity):
    """
    Promotes a user to admin
    Admin only
    Usage: /promote identity
    identity: the identity of the user, either their name or ip:port
    """
    for client_manager in client_managers:
        for client in client_manager.clients:
            if client == identity:
                if client.admin:
                    return 'That user is already an admin'
                client.admin = True
                # TODO Update db, maybe in client class
                print(f'{str(client)} was promoted')
                disseminate_message(None, action='promotion', user=str(client))
                return f'{str(client)} was promoted'
    return 'No user found'


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


standard_command_dispatch = {'help': help_command}
admin_command_dispatch = {'userinfo': userinfo, 'kick': kick, 'promote': promote}
# Admins have access to all commands, including standard ones
admin_command_dispatch.update(standard_command_dispatch)


if __name__ == '__main__':
    new_logins_queue = []
    new_salts_queue = []
    running = True

    client_managers = [ClientManager() for _ in range(MAX_CLIENT_THREADS)]
    for manager in client_managers:
        new_thread = threading.Thread(target=manager.run)
        manager.thread = new_thread

    # Create RSA keys
    pub_key, priv_key = rsa.newkeys(512)

    # Accepts new connections
    accepting_thread = threading.Thread(target=accept_connections, name='accepting')

    # Writes data to files from queues
    file_writing_thread = threading.Thread(target=write_files, name='file_writing')

    file_writing_thread.start()
    accepting_thread.start()

    while running:
        command, *args = input().split()
        if command == 'exit':
            running = False
        else:
            print(admin_command_dispatch[command](*args))

    accepting_thread.join()
    file_writing_thread.join()
    for manager in client_managers:
        try:
            manager.thread.join()
        except RuntimeError:
            pass