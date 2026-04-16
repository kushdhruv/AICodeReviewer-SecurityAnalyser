import sqlite3

def get_user(username):
    """
    Simulates fetching a user from a database.
    Contains CWE-89: SQL Injection.
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # DANGEROUS: String formatting directly into a SQL query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Exception as e:
        return str(e)
    finally:
        conn.close()
