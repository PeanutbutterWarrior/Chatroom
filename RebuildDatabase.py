import sqlite3

with open('users.db', 'w+') as file:
    pass

database = sqlite3.connect('users.db')
cursor = database.cursor()

cursor.execute("CREATE TABLE users (username, password, salt, admin DEFAULT 0)")

database.commit()
database.close()
