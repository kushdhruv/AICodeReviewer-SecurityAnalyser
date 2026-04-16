from flask import Flask, request, jsonify
from db import get_user
from utils import ping_server
import config

app = Flask(__name__)

@app.route('/user', methods=['GET'])
def user():
    username = request.args.get('username')
    # Calls another file with a SQL Injection vulnerability
    user_data = get_user(username)
    return jsonify({"data": user_data})

@app.route('/ping', methods=['POST'])
def ping():
    ip = request.form.get('ip')
    # Calls another file with an OS Command Injection vulnerability
    result = ping_server(ip)
    return jsonify({"result": result})

if __name__ == '__main__':
    # Running flask in debug mode is also a security risk
    app.run(debug=True)
