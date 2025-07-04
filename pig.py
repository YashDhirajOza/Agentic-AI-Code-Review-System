import os
import sqlite3
import hashlib
import pickle
import random
import secrets
from flask import Flask, request

app = Flask(__name__)

# 1. Hardcoded credentials
USERNAME = "admin"
PASSWORD = "123456"  # Very weak and hardcoded

# 2. Command Injection
def ping_host(host):
    os.system(f"ping -c 1 {host}")  # Vulnerable

# 3. SQL Injection
def get_user_by_name(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"  # Vulnerable
    cursor.execute(query)
    return cursor.fetchall()

# 4. Insecure Hashing
def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # Weak hash

# 5. Use of eval
def run_eval(expression):
    return eval(expression)  # Dangerous

# 6. Unsafe File Write
def write_file(filename, content):
    with open(filename, 'w') as f:
        f.write(content)  # No sanitization

# 7. Insecure Deserialization
def deserialize_data(data):
    return pickle.loads(data)  # Unsafe

# 8. XSS via Flask
@app.route('/xss')
def xss():
    name = request.args.get('name')
    return f"<h1>Hello {name}</h1>"  # Reflective XSS risk

# 9. Weak Random Token Generator
def generate_token():
    return str(random.randint(100000, 999999))  # Predictable

# 10. Insecure File Permissions
def save_secret_file():
    with open("secret.txt", "w") as f:
        f.write("top-secret")
    os.chmod("secret.txt", 0o777)  # Too permissive

# 11. Flask secret key hardcoded
app.secret_key = 'supersecretkey'

if __name__ == "__main__":
    app.run(debug=True)
