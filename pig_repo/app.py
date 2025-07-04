import os
import sqlite3
import hashlib
import pickle
import random
import secrets
from flask import Flask, request
app = Flask(__name__)
USERNAME = "admin"
PASSWORD = "123456"  
def ping_host(host):
    os.system(f"ping -c 1 {host}")
def get_user_by_name(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"  
    cursor.execute(query)
    return cursor.fetchall()
def store_password(password):
    return hashlib.md5(password.encode()).hexdigest()  
def run_eval(expression):
    return eval(expression)
def write_file(filename, content):
    with open(filename, 'w') as f:
        f.write(content)  
def deserialize_data(data):
    return pickle.loads(data)  
@app.route('/xss')
def xss():
    name = request.args.get('name')
    return f"<h1>Hello {name}</h1>"  
def generate_token():
    return str(random.randint(100000, 999999))  
def save_secret_file():
    with open("secret.txt", "w") as f:
        f.write("top-secret")
    os.chmod("secret.txt", 0o777)  
app.secret_key = 'supersecretkey'

if __name__ == "__main__":
    app.run(debug=True)
