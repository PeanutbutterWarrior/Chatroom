import socket
import threading
import ClientCommon as cc
import PySimpleGUI as sg

HOST = 'localhost'
PORT = 26950


def listen(connection):
    while True:
        try:
            message = cc.receive(connection)
        except ConnectionResetError:
            window['chat'].print('Disconnected')
            break

        # TODO turn this into functions and a dispatch dictionary
        if message['action'] == 'send':
            window['chat'].print(f'{message["user"]}: {message["text"]}')
        elif message['action'] == 'connection':
            window['chat'].print(f'{message["user"]} connected')
        elif message['action'] == 'disconnection':
            window['chat'].print(f'{message["user"]} disconnected')
        elif message['action'] == 'command-response':
            window['chat'].print(message["text"])
        elif message['action'] == 'kick':
            window['chat'].print(f'{message["user"]} was kicked')
        elif message['action'] == 'promotion':
            window['chat'].print(f'{message["user"]} was promoted')


WIDTH = 750
HEIGHT = 750

login_layout = [[sg.Text(text='Username:')],
                [sg.Input(tooltip='Username', key='-username-')],
                [sg.Text(text='Password:')],
                [sg.Input(tooltip='Password', key='-password-', password_char='*')],
                [sg.Button(button_text='Log In', key='login'),
                 sg.Button(button_text='Register', key='register'),
                 sg.Button(button_text='Listen', key='listen')],
                [sg.Text(key='error', visible=False, size=(25, None))]]

chat_layout = [[sg.Multiline(default_text='Connected to server\n', disabled=True,
                             auto_refresh=True, size=(100, 25), key='chat')],
               [sg.Input(tooltip='Message', key='-message-'),
                sg.Button(button_text='Send', key='send')]]

layout = [[sg.Column(login_layout, key='loginlayout'), sg.Column(chat_layout, key='chatlayout', visible=False)]]

username = None

window = sg.Window('ClientGUI', layout, finalize=True)
window['error'].Widget.configure(wraplength=300)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    listening_thread = threading.Thread(target=listen, args=(s,), daemon=True)
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            break
        elif event == 'send':
            if values['-message-']:
                if values['-message-'][0] == '/':
                    command, *args = values['-message-'].split(' ')
                    command = command[1:]
                    cc.send(s, action='command', command=command, args=args)
                else:
                    cc.send(s, action='message', text=values['-message-'])
                window['-message-'].update(value='')
                window['chat'].print(f'{username}: {values["-message-"]}')

        elif event == 'login':
            username_ok = cc.check_username(values['-username-'])
            if username_ok is not True:
                window['error'].update(value=username_ok, visible=True)
                continue
            
            password_ok = cc.check_password(values['-password-'])
            if password_ok is not True:
                window['error'].update(value=password_ok, visible=True)
            
            username = values['-username-']
            password = cc.encrypt_password(values['-password-'], s)
            cc.send(s, action='login', username=username, password=password)
            
            response = cc.receive(s)
            if response['ok']:
                window['loginlayout'].update(visible=False)
                window['chatlayout'].update(visible=True)
                listening_thread.start()
            else:
                window['error'].update(value=response['reason'], visible=True)
            
        elif event == 'register':
            username_ok = cc.check_username(values['-username-'])
            if username_ok is not True:
                window['error'].update(value=username_ok, visible=True)
                continue

            password_ok = cc.check_password(values['-password-'])
            if password_ok is not True:
                window['error'].update(value=password_ok, visible=True)

            username = values['-username-']
            password = cc.encrypt_password(values['-password-'], s)
            cc.send(s, action='register', username=username, password=password)
            
            response = cc.receive(s)
            if response['ok']:
                window['register'].update(visible=False)
            else:
                window['error'].update(value=response['reason'], visible=True)
            
        elif event == 'listen':
            cc.send(s, action='listen')
            window['loginlayout'].update(visible=False)
            window['chatlayout'].update(visible=True)
            listening_thread.start()
