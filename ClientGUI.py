import socket
import threading
import json
import hashlib
import PySimpleGUI as sg


# Characters allowed in usernames and passwords
allowed_chars = set('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_=+')


def check_username(username):
    if len(username) > 16:
        return False
    for char in username:
        if char not in allowed_chars:
            return False
    return True


def check_password(password):
    if len(password) > 32:
        return False
    for char in password:
        if char not in allowed_chars:
            return False
    return True


def limit_size(size, var):
    def to_return(*args):
        var.set(var.get()[:size])
    return to_return


def login(data):
    username = data['-username-']
    password = data['-password-']
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    s.sendall(json.dumps({'action': 'login',
                          'username': username,
                          'password': password}).encode('utf-8'))
    response = json.loads(s.recv(1024))
    if not response['ok']:
        window['error'].update(value=response, visible=True)


def register(data):
    username = data['-username-']
    if not check_username(username):
        window['error'].update(value='Invalid username. Allowed characters are letters, numbers, '
                                     '-, _ , = and +. No diacritics are allowed.', visible=True)
        return

    password = data['-username-']
    if not check_password(password):
        window['error'].update(value='Invalid password. Allowed characters are letters, numbers, -, _ '
                                     ', = and +. No diacritics are allowed.', visible=True)
        return
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()

    s.sendall(json.dumps({'action': 'register',
                          'username': username,
                          'password': password}).encode('utf-8'))
    response = json.loads(s.recv(1024))

    if not response['ok']:
        window['error'].update(value=response, visible=True)
    else:
        login(data)


def send_message():
    message = chat_entry_box.get()
    chat_entry_box_text.set('')
    data = json.dumps({'action': 'send', 'text': message})
    s.sendall(data.encode('utf-8'))


HOST = '192.168.2.11'
PORT = 56789

WIDTH = 750
HEIGHT = 750

layout = [[sg.Input(default_text='Username', tooltip='Username', key='-username-')],
          [sg.Input(default_text='Password', tooltip='Password', key='-password-')],
          [sg.Button(button_text='Log In', key='login')],
          [sg.Button(button_text='Register', key='register')],
          [sg.Text(key='error', visible=False)]]

window = sg.Window('ClientGUI', layout, finalize=True)
window['error'].Widget.configure(wraplength=200)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            break
        elif event == 'login':
            login(values)
        elif event == 'register':
            register(values)
        print(event, values)

exit()
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Either create a login for a user or log them in
    if new_user:
        while True:
            s.sendall(json.dumps({'action': 'register', 'username': username, 'password': password}).encode('utf-8'))
            response = json.loads(s.recv(1024))
            if response['ok']:
                break
            if response['reason'] == 1:
                print('Username is in use. Choose a different one')
                username = get_username(new_user)
        s.sendall(json.dumps({'action': 'login', 'username': username, 'password': password}).encode('utf-8'))
        s.recv(1024)
    else:
        while True:
            s.sendall(json.dumps({'action': 'login', 'username': username, 'password': password}).encode('utf-8'))
            response = json.loads(s.recv(1024))
            if response['ok']:
                break
            if response['reason'] == 1:
                print('Incorrect username. Please reenter')
                username = get_username(new_user)
            elif response['reason'] == 2:
                print('Incorrect password. Please reenter')
                password = get_password(new_user)

    sending_thread = threading.Thread(target=send_messages, args=(s,), daemon=True)
    sending_thread.start()
    while True:
        try:
            received = s.recv(1024)
        except ConnectionResetError:
            print('Connection closed by server')
            break
        received = json.loads(received)
        if received['action'] == 'send':
            print(f'{received["user"]}: {received["text"]}')
        elif received['action'] == 'connection':
            print(f'{received["user"]} connected')
        elif received['action'] == 'disconnection':
            print(f'{received["user"]} disconnected')
