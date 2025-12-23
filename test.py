import sqlite3

def check_users():
    conn = sqlite3.connect('voting_system.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    for user in users:
        print(user)  # Display the users' details to verify
    conn.close()

check_users()
