import socket
import threading
import json
import ClientCommon as cc
import PySimpleGUI as sg

HOST = '192.168.2.11'
PORT = 26951


def listen(connection):
    while True:
        try:
            data = connection.recv(1024)
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


WIDTH = 750
HEIGHT = 750

login_layout = [[sg.Input(default_text='Username', tooltip='Username', key='-username-')],
                [sg.Input(default_text='Password', tooltip='Password', key='-password-')],
                [sg.Button(button_text='Log In', key='login')],
                [sg.Button(button_text='Register', key='register')],
                [sg.Text(key='error', visible=False, size=(25, None))]]

chat_layout = [[sg.Multiline(default_text='Connected to server\n', disabled=True,
                             auto_refresh=True, size=(100, 50), key='chat')],
               [sg.Input(tooltip='Message', key='-message-'),
                sg.Button(button_text='Send', key='send')]]

layout = [[sg.Column(login_layout, key='loginlayout'), sg.Column(chat_layout, key='chatlayout', visible=False)]]

window = sg.Window('ClientGUI', layout, finalize=True)
window['error'].Widget.configure(wraplength=300)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    listening_thread = threading.Thread(target=listen, args=(s,), daemon=True)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            break
        elif event == 'login':
            logged_in = cc.login(values['-username-'], values['-password-'], s)
            if logged_in is True:
                window['loginlayout'].update(visible=False)
                window['chatlayout'].update(visible=True)
                listening_thread.start()
            else:
                window['error'].update(value=logged_in, visible=True)
        elif event == 'register':
            registered = cc.register(values['-username-'], values['-password-'], s)
            if registered is True:
                cc.login(values['-username-'], values['-password-'], s)
                window['register'].update(visible=False)
            else:
                window['error'].update(value=registered, visible=True)
        elif event == 'send':
            if values['-message-']:
                cc.send_message(values['-message-'], s)
                window['-message-'].update(value='')
                window['chat'].print(values['-message-'])
        else:
            print(event)
