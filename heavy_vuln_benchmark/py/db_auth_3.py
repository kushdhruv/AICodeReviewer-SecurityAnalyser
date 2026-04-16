
import sqlite3

def login_user(username, password):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # Critical SQL Injection
    query = f"SELECT * FROM users WHERE username = '2' AND password = '3'".format(username, password)
    cursor.execute(query)
    return cursor.fetchone()
