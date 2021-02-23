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


def login(username, password):
    password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    s.sendall(json.dumps({'action': 'login',
                          'username': username,
                          'password': password}).encode('utf-8'))
    response = json.loads(s.recv(1024))
    if not response['ok']:
        window['error'].update(value=response, visible=True)


def register(username, password):
    if not check_username(username):
        window['error'].update(value='Invalid username. Allowed characters are letters, numbers, '
                                     '-, _ , = and +. No diacritics are allowed.', visible=True)
        return

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
        login(username, password)


def send_message(data):
    message = json.dumps({'action': 'send', 'text': data})
    s.sendall(message.encode('utf-8'))


def listen():
    while True:
        try:
            data = s.recv(1024)
            if not data:
                raise ConnectionResetError
        except ConnectionResetError:
            window['chat'].print('Disconnected')
            break
        print(data)
        received = json.loads(data)
        if received['action'] == 'send':
            window['chat'].print(f'{received["user"]}: {received["text"]}')
        elif received['action'] == 'connection':
            window['chat'].print(f'{received["user"]} connected')
        elif received['action'] == 'disconnection':
            window['chat'].print(f'{received["user"]} disconnected')


HOST = '192.168.2.11'
PORT = 26951

WIDTH = 750
HEIGHT = 750

login_layout = [[sg.Input(default_text='Username', tooltip='Username', key='-username-')],
                [sg.Input(default_text='Password', tooltip='Password', key='-password-')],
                [sg.Button(button_text='Log In', key='login')],
                [sg.Button(button_text='Register', key='register')],
                [sg.Text(key='error', visible=False)]]

chat_layout = [[sg.Multiline(default_text='Connected to server\n', disabled=True,
                             auto_refresh=True, size=(100, 50), key='chat')],
               [sg.Input(tooltip='Message', key='-message-', size=(100, None)),
                sg.Button(button_text='Send', key='send')]]

layout = [[sg.Column(login_layout, key='loginlayout'), sg.Column(chat_layout, key='chatlayout', visible=False)]]

window = sg.Window('ClientGUI', layout, finalize=True)
window['error'].Widget.configure(wraplength=200)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    listening_thread = threading.Thread(target=listen, daemon=True)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            break
        elif event == 'login':
            login(values['-username-'], values['-password-'])
            window['loginlayout'].update(visible=False)
            window['chatlayout'].update(visible=True)
            listening_thread.start()
        elif event == 'register':
            register(values['-username-'], values['-password-'])
        elif event == 'send':
            if values['-message-']:
                send_message(values['-message-'])
                window['-message-'].update(value='')
                # window['chat'].print('\n')
                window['chat'].print(values['-message-'])
        else:
            print(event)
