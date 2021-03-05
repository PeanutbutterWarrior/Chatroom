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

# Will spawn this many ClientManagers at most each with a thread, plus two extra threads, plus the main thread
MAX_CLIENT_THREADS = 8


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
                        getattr(client, data['action'])(data)

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
        self.color = None
        self.cursor = self.db.cursor()
        self.logged_in = False
        self.receiving = False
        self.admin = False

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
            disseminate_message(self, action='send', text=data['text'], user=str(self), color=self.color)

    def command(self, data):
        if self.admin:
            dispatch = admin_command_dispatch
        else:
            dispatch = standard_command_dispatch

        try:
            self.send(action='command-response', text=dispatch[data['command']](self, *data['args']))
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
        if self.cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone() is None:
            self.send(ok=False, reason='There is no account with that name', force_send=True)
            return

        self.cursor.execute('SELECT salt FROM users WHERE username = ?', (username,))
        salt = self.cursor.fetchone()[0]
        password, _ = hash_password(data['password'], salt=salt)
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
            self.color = self.cursor.execute("SELECT color FROM users WHERE username = ?", (username,)).fetchone()[0]
            print(f'{self.identity} logged in as {username}')
            disseminate_message(self, action='connection', user=str(self))

    def register(self, data):
        username = data['username']

        if self.cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            self.send(ok=False, reason='That username is already in use', force_send=True)
        else:
            password, salt = hash_password(data['password'])
            self.send(ok=True, force_send=True)
            print(f'New user {username}')
            new_logins_queue.put((username, password, salt), block=False)

    def get_color(self, data):
        self.send(command='color', color=self.color)

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
    db = sqlite3.connect('users.db', isolation_level=None)
    cursor = db.cursor()
    while running:
        while not new_logins_queue.empty():
            try:
                login = new_logins_queue.get(block=False)
            except queue.Empty:
                break
            cursor.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)', login)
        while not changed_logins_queue.empty():
            try:
                column, *values = changed_logins_queue.get(block=False)
            except queue.Empty:
                break
            column = sanitise_string(column)  # Cannot use usual insertion so must manually sanitise and insert
            cursor.execute(f'UPDATE users SET {column} = ? WHERE username = ?', values)
    db.commit()
    db.close()


def sanitise_string(string):
    sanitised = []
    for char in string:
        if char.isalnum():  # a-z A-Z 0-9
            sanitised.append(char)
    return ''.join(sanitised)


def hash_password(password, salt=None):
    password = bytes.fromhex(password)
    password = rsa.decrypt(password, priv_key)
    password_hash = hashlib.sha256(password)
    if salt is None:
        salt = secrets.token_hex(32)
    password_hash.update(bytes.fromhex(salt))
    password_hash = password_hash.hexdigest()
    return password_hash, salt


# Commands


def userinfo(caller, identity):
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


def kick(caller, identity, mask='none'):
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


def promote(caller, identity):
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
                if client.logged_in:
                    changed_logins_queue.put(('admin', 1, client.name), block=False)
                disseminate_message(caller, action='promotion', user=str(client))
                return f'{str(client)} was promoted'
    return 'No user found'


def help_command(caller, command_name):
    """
    Gives information on the usage of a command
    Usage: /help command_name
    command_name: The name of the command
    """
    try:
        return inspect.getdoc(admin_command_dispatch[command_name])
    except IndexError:
        return 'No command with that name'


def change_username(caller, new_name):
    """
    Changes your username
    Usage: /username new_name
    new_name: The name you want to change your username to
    """
    if caller.logged_in:
        print(f'Changing {caller.name}\'s name to {new_name}')
        disseminate_message(caller, action='send', text=f'{caller.name} changed their name to {new_name}')
        changed_logins_queue.put(('username', new_name, caller.name), block=False)
        caller.name = new_name
        return f'You have changed your name to {new_name}'
    return 'You are not logged in'


def change_password(caller, new_password):
    """
    Changes your password
    Usage: /password new_password
    new_password: The password you want to change your password to
    """
    if caller.logged_in:
        print(f'{caller} changed their password')
        new_password, salt = hash_password(new_password)
        changed_logins_queue.put(('password', new_password, caller.name), block=False)
        changed_logins_queue.put(('salt', salt, caller.name), block=False)
        return 'You have changed your password'
    return 'You are not logged in'


def demote(caller, identity):
    """
    Demotes a user from admin
    Admin only
    Usage: /demote identity
    identity: the identity of the user, either their name or ip:port
    """
    for client_manager in client_managers:
        for client in client_manager.clients:
            if client == identity:
                if not client.admin:
                    return 'That user is not an admin'
                client.admin = False
                if client.logged_in:
                    changed_logins_queue.put(('admin', 0, client.name), block=False)
                print(f'{str(client)} was demoted')
                disseminate_message(caller, action='demotion', user=str(client))
                return f'{str(client)} was demoted'
    return 'No user found'


def change_color(caller, new_color):
    """
    Changes your text color
    Usage: /color new_color
    new_color: Either a name of a color or a hex color code in the format #******
    """
    if caller.logged_in:
        print(f'{caller} changed their color to {new_color}')
        changed_logins_queue.put(('color', new_color, caller.name))
        caller.color = new_color
        return 'You have changed your color'
    return 'You are not logged in'


standard_command_dispatch = {'help': help_command, 'username': change_username, 'password': change_password,
                             'color': change_color}
admin_command_dispatch = {'userinfo': userinfo, 'kick': kick, 'promote': promote, 'demote': demote}
# Admins have access to all commands, including standard ones
admin_command_dispatch.update(standard_command_dispatch)


if __name__ == '__main__':
    new_logins_queue = queue.Queue()
    changed_logins_queue = queue.Queue()
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
            print(admin_command_dispatch[command]('', *args))

    accepting_thread.join()
    file_writing_thread.join()
    for manager in client_managers:
        try:
            manager.thread.join()
        except RuntimeError:
            pass