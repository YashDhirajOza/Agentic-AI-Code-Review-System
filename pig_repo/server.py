import os
from flask import Flask, request, jsonify
from app.config import SECRET_KEY, LOG_PATH
from app.utils import run_unvalidated_eval, load_user_data, ping_host
import get_user
import logging

app = Flask(__name__)
app.secret_key = SECRET_KEY  
logging.basicConfig(filename=LOG_PATH, level=logging.INFO)

@app.route('/eval')
def unsafe_eval_endpoint():
    expr = request.args.get('expr', '')
    logging.info(f"Evaluating expression: {expr}")
    result = run_unvalidated_eval(expr)  
    return jsonify({'result': result})

@app.route('/deserialize', methods=['POST'])
def unsafe_deserialize_endpoint():
    data = request.get_data()
    logging.info("Deserializing user data")
    obj = load_user_data(data)  
    return jsonify({'obj_repr': repr(obj)})

@app.route('/ping')
def ping_endpoint():
    host = request.args.get('host', '')
    logging.info(f"Pinging host: {host}")
    output = ping_host(host)  
    return jsonify({'output': output})

@app.route('/user')
def user_info_endpoint():
    username = request.args.get('username', '')
    logging.info(f"Fetching user: {username}")
    info = get_user(username)  
    return jsonify({'user': [dict(row) for row in info]})

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Unhandled exception: {e}")
    return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
