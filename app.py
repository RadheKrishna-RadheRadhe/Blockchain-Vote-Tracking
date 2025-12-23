import sqlite3
from flask import Flask, render_template, request, redirect, session, flash, jsonify, send_file
from blockchain import Blockchain
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import io
from Crypto.Cipher import AES
import binascii
import os

app = Flask(__name__, static_folder='templates/static')
app.secret_key = "supersecret"  # Needed for sessions

# AES key – store this securely!
# You can use an environment variable in production
KEY_HEX = "df1691257d753ffc96f06edec78116182607c1ff3973ed7e3bb035bce871f1bb"
IV_HEX = "f191c79a6ab0f7be391eb1f2407a2074"

AES_KEY = binascii.unhexlify(KEY_HEX)   # 32 bytes (AES-256)
AES_IV = binascii.unhexlify(IV_HEX)     # 16 bytes (AES block size)

# Initialize blockchain
bc = Blockchain()
election_active = False

# Database connection function
def get_db_connection():
    conn = sqlite3.connect('voting_system.db')
    conn.row_factory = sqlite3.Row
    return conn

# --- AUTH ROUTES ---
@app.route('/')
def home():
    if session.get('user'): # If a user is logged in, show them a different message
        return redirect('/vote')  # Or direct to a user-specific page, like the vote page
    
    return render_template('home.html')  # Home page will contain login/register buttons

# --- LOGIN ROUTE ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):  # Verify hashed password
            session['user'] = user['username']
            session['role'] = user['role']  # Save role in session
            if user['role'] == 'admin':
                return redirect('/admin/dashboard')  # Redirect admin to dashboard
            else:
                return redirect('/vote')  # Redirect voters to voting page
        else:
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
    
    return render_template('login.html')


# --- REGISTER ROUTE ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if user already exists
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        # Hash the password before saving it
        hashed_password = generate_password_hash(password)
        
        # Insert new user into the database with hashed password
        conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, 'voter'))
        conn.commit()
        conn.close()
        
        flash('Registration successful. Please log in.', 'success')
        return redirect('/login')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# --- VOTING ROUTES ---
@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if not session.get('user'):
        flash('Please login to vote.', 'danger')
        return redirect('/login')

    voter = session['user']
    conn = get_db_connection()
    user_vote = conn.execute(
        'SELECT * FROM votes WHERE user_id = (SELECT id FROM users WHERE username = ?)', (voter,)
    ).fetchone()
    conn.close()

    if user_vote:
        return render_template('already_voted.html')

    if request.method == 'POST':
        candidate = request.form['candidate']
        conn = get_db_connection()
        user_id = conn.execute('SELECT id FROM users WHERE username = ?', (voter,)).fetchone()['id']
        conn.execute(
            'INSERT INTO votes (user_id, candidate, timestamp) VALUES (?, ?, ?)',
            (user_id, candidate, datetime.now())
        )
        conn.commit()
        conn.close()

        bc.add_vote(voter, candidate)  # Add vote to blockchain too
        return redirect('/vote/confirmation')

    return render_template('vote.html', candidates=["Bharatiya Janata Party |BJP|", "Indian National Congress |INC|", "Communist Party of India |CPI (M)|", "Aam Aadmi Party |AAP|", "National People's Party |NPP|", "Bahujan Samaj Party |BSP|"])

@app.route('/vote/confirmation')
def confirmation():
    return render_template('confirmation.html')

# --- RESULTS ROUTE ---
@app.route('/results')
def results():
    # Count votes per candidate
    vote_counts = {}
    for block in bc.chain[1:]:  # skip genesis block
        if block.candidate != "None":
            vote_counts[block.candidate] = vote_counts.get(block.candidate, 0) + 1
    return render_template('results.html', vote_counts=vote_counts)

# --- ADMIN ROUTES ---
@app.route('/admin/dashboard')
def admin_dashboard():
    # Ensure the user is logged in and is an admin
    if session.get('role') != 'admin':
        flash("You don't have permission to access this page", 'danger')
        return redirect('/login')  # Redirect to login if not an admin
    return render_template('admin_dashboard.html')

@app.route('/admin/blockchain')
def admin_blockchain():
    return render_template('blockchain_view.html', chain=bc.chain)

@app.route("/admin/export")
def export_results():
    if session.get("role") != "admin":
        flash("Access denied!", "danger")
        return redirect("/")

    conn = sqlite3.connect("voting_system.db")
    df = pd.read_sql_query("SELECT * FROM votes", conn)
    conn.close()

    if df.empty:
        flash("No votes to export!", "info")
        return redirect("/admin/dashboard")

    # Convert results to CSV
    csv_data = df.to_csv(index=False).encode("utf-8")

    # --- AES Encryption (CBC Mode) ---
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)

    # Add PKCS#7 padding
    pad_len = 16 - (len(csv_data) % 16)
    csv_data += bytes([pad_len] * pad_len)

    ciphertext = cipher.encrypt(csv_data)

    encrypted_file = io.BytesIO(ciphertext)
    encrypted_file.seek(0)

    flash("Results exported successfully (AES-256 Encrypted)!", "success")

    return send_file(
        encrypted_file,
        as_attachment=True,
        download_name="election_results.aes",
        mimetype="application/octet-stream"
    )

# --- ERROR ROUTES ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)