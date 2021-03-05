# Chatroom

## Usage

### Client
 - Use **ClientGUI.py** for a graphical interface. This requires the rsa library and the PySimpleGUI library.
 - Use **ClientCommandLine.py** for a command line interface. This only requires the rsa library.
 - All required libraries can be installed with the command `pip install -r requirements.txt`
 - Both scripts require **ClientCommon.py** to be in the same directory as it.
 - Open **ClientGUI.py** or **ClientCommandLine.py** in a text editor and change the `host` and `port` variables to 
   point to the server. `host` should be an IPv4 address as a string, or `'localhost'` if the server is running on your 
   machine. `port` should be the outward facing port of the server. If the client and server are running on the same 
   machine then the port is the same as the port chosen in Server.py.
 - Save, close and run the script. You then have to log in or register an account with a username and password. You can
   also listen, which does not require an account, but you will only be able to see messages, you cannot send any 
   yourself. You can still run some commands.
 - Commands are prefixed by `/`. They are not necessarily seen by other users. Use `/help` to get more information.

### Server
 - Open Server.py and change the `host` and `port` variables to set the address of the server. `host` should generally 
   a `'0.0.0.0'` to accept connections from the internet or your own machine. Set it to `'localhost'` to only accept 
   connections from your own machine. `port` should be the port to listen for connections on. If you want people to be 
   able to connect over the internet you will need to create a port forwarding rule on your router which forwards
   connections from any outward facing port to the port you have chosen. The ip should be the private ip of the machine 
   the server is running on. The outward facing port is the port clients should connect to. _Note that each client will
   communicate over a separate port. These are dynamically allocated at runtime automatically._
 - You can change `MAX_CLIENT_THREADS` to change the maximum number of threads that will be used. `MAX_CLIENT_THREADS` 
   plus 3 will be used at most, including the main thread.
 - Save your changes and close the file.
 - To create the database used to store user logins either rename **example_users.db** to **users.db** or run
   **RebuildDatabase.py**. **example_users.db** comes with an account _admin_ with the password _admin_ which has admin
   privileges. It is advised to change the password immediately.
 - Run **Server.py**.
 - Information about user's activity will be printed to the console. Commands can also be entered here. The commands
   available are a subset of those available to users, excluding those that are used to change account information.


## Security
 - Passwords are sent over the network encrypted with RSA. The public and private key-pair are changed every time the
   **Server.py** is run. Passwords are stored by the server combined with a random salt and hashed with SHA-256. The 
   plaintext password is never stored and cannot be decrypted. If you lose your password then  you must create a new 
   account.
 - Passwords are not vulnerable to timing attacks as a constant-time algorithm is used to compare them.
 - Communications are vulnerable to man in the middle attacks as there is no third-party to verify RSA keys. An attacker
   can always pretend to be the server, including issuing its own RSA key-pair.
 - Most messages sent are not encrypted, only passwords are. This is to achieve better performance.

## Performance
 - There is a noticeable lag between a message being sent and other users receiving it. This is due to outbound
   messages only being sent by the server once per second. This time can be decreased at the cost of decreasing overall
   performance.
 - Multiple threads are used by the server to send and receive messages to and from clients. This is to decrease the
   delay in sending a message from one client if another client has sent a large message. Increasing the number of
   threads used will decrease the number of clients impacted by one sending a very large message, however it will
   decrease general performance as each thread comes with some overhead.