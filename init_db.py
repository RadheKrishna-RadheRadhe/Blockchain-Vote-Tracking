import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    conn = sqlite3.connect('voting_system.db')
    c = conn.cursor()
    
    # Create table for users (voter/admin)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT CHECK(role IN ('voter', 'admin')),
                    voted BOOLEAN DEFAULT FALSE
                )''')
    
    # Create table for votes (track if user voted)
    c.execute('''CREATE TABLE IF NOT EXISTS votes (
                    user_id INTEGER,
                    candidate TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )''')
    
    
    conn.commit()

    # Example SQL query to insert an admin into the users table
    conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
             ('admin_user', generate_password_hash('adminpassword'), 'admin'))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()