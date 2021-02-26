import hashlib
import inspect
import json
import rsa
import secrets
import socket
import sqlite3
import threading

HOST = '0.0.0.0'
PORT = 26951


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
        self.dispatch = {'send': self.receive, 'command': self.command, 'get_key': self.get_key, 'listen': self.listen,
                         'logout': self.logout, 'login': self.login, 'register': self.register}

    def run(self):
        with self.connection:
            while True:
                try:
                    data = self.connection.recv(1024)
                    if not data:
                        raise ConnectionResetError
                except BlockingIOError:
                    continue
                except ConnectionResetError:
                    print(f'{str(self)} disconnected')
                    if self.logged_in:
                        disseminate_message(self, action='disconnection', user=str(self))
                    break

                data = json.loads(data)
                self.dispatch[data['action']](data)
        self.cursor.close()
        users.remove(self)

    # Message actions

    def receive(self, data):
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
        while len(new_logins_queue) > 0:
            pass
        if self.cursor.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone() is None:
            self.send(ok=False, reason='There is no account with that name', force_send=True)
            return

        password = self.hash_password(data['password'])
        while len(new_salts_queue) > 0:
            pass
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

    # Helper methods

    def send(self, force_send=False, **kwargs):
        if self.receiving or force_send:
            try:
                self.connection.sendall(json.dumps(kwargs).encode('utf-8'))
            except OSError:
                pass

    def send_raw(self, message, force_send=False):
        if self.receiving or force_send:
            try:
                self.connection.sendall(message)
            except OSError:
                pass

    @staticmethod
    def hash_password(password):
        password = bytes.fromhex(password)
        password = rsa.decrypt(password, priv_key)
        return hashlib.sha256(password)

    # Magic methods

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


def disseminate_message(origin, **kwargs):
    message = json.dumps(kwargs).encode('utf-8')
    for user in users:
        if user != origin:
            user.send_raw(message)


def accept_connections():
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
            users.append(client)
            client_thread = threading.Thread(target=client.run, daemon=True, name=identity+'-client')
            client_thread.start()


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
    for user in users:
        if user == identity:
            return str(user)
    return 'No user found'


def kick(identity, mask='none'):
    """
    Kicks a user from the server. Does not stop them reconnecting
    Admin only
    Usage: /kick identity [mask='none']
    identity: the identity of the user, either their name or ip:port
    mask: 'none', 'disconnect' or 'hidden'. Hides or changes the kicking
    """
    for user in users:
        if user == identity:
            if mask == 'none':
                disseminate_message(identity, action='kick', user=str(user))
            elif mask == 'disconnect':
                disseminate_message(identity,  action='disconnect', user=str(user))
            elif mask == 'hidden':
                pass
            else:
                raise TypeError  # Gets caught at calling of command
            user.send(action='send', text='You have been kicked', user='[Server]')
            print(f'{str(user)} was kicked')
            user.connection.close()
            return f'{str(user)} was kicked'
    return 'No user found'


def debug():
    """
    Gives debug information. Only prints to the server console
    Usage: /debug
    """
    print(users)
    print(new_logins_queue)
    print(new_salts_queue)
    print(running)


def promote(identity):
    """
    Promotes a user to admin#
    Admin only
    Usage: /promote identity
    identity: the identity of the user, either their name or ip:port
    """
    for user in users:
        if user == identity:
            if user.admin:
                return 'That user is already an admin'
            user.admin = True
            # TODO Update db, maybe in client class
            print(f'{str(user)} was promoted')
            disseminate_message(None, action='promotion', user=str(user))
            return f'{str(user)} was promoted'
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


standard_command_dispatch = {'debug': debug, 'help': help_command}
admin_command_dispatch = {'userinfo': userinfo, 'kick': kick, 'promote': promote}
# Admins have access to all commands, including standard ones
admin_command_dispatch.update(standard_command_dispatch)


if __name__ == '__main__':
    users = []
    new_logins_queue = []
    new_salts_queue = []
    running = True

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
