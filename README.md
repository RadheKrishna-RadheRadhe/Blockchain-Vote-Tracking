# 🗳️ Blockchain-Based Secure Online Voting System

A secure web-based voting application built using **Flask**, **SQLite**, **Blockchain**, and **AES-256 encryption**.  
The system ensures **vote integrity**, **one-person-one-vote**, **data confidentiality**, and **tamper resistance**.

---

## 📌 Features

### 👤 User Authentication
- Secure registration & login
- Passwords hashed using Werkzeug
- Role-based access (Admin / Voter)

### 🗳️ Voting System
- Each voter can vote only once
- Votes stored in SQLite database
- Votes simultaneously added to a Blockchain ledger

### 🔗 Blockchain Security
- Each vote is a block
- SHA-256 hashing
- Immutable vote records
- Genesis block initialization
- Chain integrity verification

### 🔐 Data Encryption
- Election results exported as AES-256-CBC encrypted file
- PKCS#7 padding applied
- Separate decryption utility provided

### 👨‍💼 Admin Panel
- Admin dashboard
- Blockchain view
- Encrypted results export

---

## 🛠️ Technologies Used

- Flask (Python)
- SQLite
- Custom Blockchain
- AES-256 Encryption (PyCryptodome)
- Pandas
- Werkzeug Security

---

## 📂 Project Structure

project/
├── app.py
├── blockchain.py
├── init_db.py
├── decrypt_results.py
├── voting_system.db
├── templates/
└── templates/static/

---

## ⚙️ Installation

```bash
pip install flask pandas pycryptodome werkzeug
```

```bash
python init_db.py
python app.py
```

---

## 🔑 Default Admin Credentials

Username: admin_user  
Password: adminpassword  

---

## 🔓 Decrypt Results

```bash
python decrypt_results.py
```

---

## 🚀 Future Enhancements

- Smart contracts
- Distributed blockchain
- Biometric authentication
- Real-time analytics

---

## 👨‍💻 Author

Shailendra Kumar
