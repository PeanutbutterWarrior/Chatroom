import sqlite3

with open('users.db', 'w+') as file:
    pass

database = sqlite3.connect('users.db')
cursor = database.cursor()

cursor.execute("CREATE TABLE users (username, password, admin)")
cursor.execute("CREATE TABLE salts (username, salt)")

database.commit()
database.close()
