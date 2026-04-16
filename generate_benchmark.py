import os
import zipfile

def create_heavy_benchmark():
    os.makedirs("heavy_vuln_benchmark/py", exist_ok=True)
    os.makedirs("heavy_vuln_benchmark/js", exist_ok=True)

    # ----------------------------------------------------
    # Generate 15 Python Vulnerable Files
    # ----------------------------------------------------
    python_templates = [
        # SQL Injection (CWE-89)
        ("heavy_vuln_benchmark/py/db_auth_{}.py", """
import sqlite3

def login_user(username, password):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # Critical SQL Injection
    query = f"SELECT * FROM users WHERE username = '{0}' AND password = '{1}'".format(username, password)
    cursor.execute(query)
    return cursor.fetchone()
"""),
        # OS Command Injection (CWE-78)
        ("heavy_vuln_benchmark/py/sys_utils_{}.py", """
import os

def ping_host(host):
    # Critical OS Command Injection
    return os.popen("ping -c 4 " + host).read()

def netstat_port(port):
    return os.popen(f"netstat -an | grep {0}").read()
"""),
        # Unsafe Deserialization (CWE-502)
        ("heavy_vuln_benchmark/py/config_parser_{}.py", """
import pickle
import yaml

def load_session(data):
    # Unsafe pickle load
    return pickle.loads(data)

def parse_yaml_config(yaml_str):
    # Unsafe yaml load
    return yaml.load(yaml_str, Loader=yaml.Loader)
"""),
        # Server-Side Request Forgery (CWE-918)
        ("heavy_vuln_benchmark/py/web_fetcher_{}.py", """
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    # SSRF vulnerability
    resp = requests.get(url) 
    return resp.text
"""),
        # Hardcoded Secrets (CWE-798)
        ("heavy_vuln_benchmark/py/aws_cred_{}.py", """
class Config:
    AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7{0}EXAMPLE"
    AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    DB_PASSWORD = "super_secret_password_123!"
""")
    ]

    py_count = 1
    for template_name, template_code in python_templates:
        for i in range(3): # Create 3 variations of each template = 15 files
            with open(template_name.format(py_count), "w") as f:
                f.write(template_code.replace("{0}", str(i)).replace("{1}", str(i+1)))
            py_count += 1

    # ----------------------------------------------------
    # Generate 15 JS Vulnerable Files
    # ----------------------------------------------------
    js_templates = [
        # Eval Injection (CWE-94)
        ("heavy_vuln_benchmark/js/calculator_{}.js", """
const express = require('express');
const app = express();

app.get('/calc', (req, res) => {
    let expression = req.query.expr;
    // Critical Eval Injection
    let result = eval(expression);
    res.send("Result: " + result);
});
"""),
        # Path Traversal (CWE-22)
        ("heavy_vuln_benchmark/js/file_server_{}.js", """
const fs = require('fs');
const path = require('path');
const express = require('express');
const app = express();

app.get('/download', (req, res) => {
    let filename = req.query.file;
    // Critical Path Traversal
    let filePath = path.join(__dirname, 'public', filename);
    res.sendFile(filePath);
});
"""),
        # Hardcoded JWT Secrets (CWE-798)
        ("heavy_vuln_benchmark/js/auth_{}.js", """
const jwt = require('jsonwebtoken');

function generateToken(user) {
    // Hardcoded JWT Secret
    const JWT_SECRET = "my_super_secret_jwt_key_12345_{0}";
    return jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
}
"""),
        # Prototype Pollution (CWE-1321)
        ("heavy_vuln_benchmark/js/utils_{}.js", """
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            // Prototype pollution vulnerability
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
"""),
        # Cross-Site Scripting (XSS) (CWE-79)
        ("heavy_vuln_benchmark/js/render_{}.js", """
function renderWelcomePage(req, res) {
    let username = req.query.username;
    // Reflected XSS
    let html = "<html><body><h1>Welcome, " + username + "!</h1></body></html>";
    res.send(html);
}
""")
    ]

    js_count = 1
    for template_name, template_code in js_templates:
        for i in range(3): # Create 3 variations of each template = 15 files
            with open(template_name.format(js_count), "w") as f:
                f.write(template_code.replace("{0}", str(i)))
            js_count += 1

    # Zip the generated files
    with zipfile.ZipFile('heavy_benchmark.zip', 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk('heavy_vuln_benchmark'):
            for file in files:
                zipf.write(os.path.join(root, file), 
                           os.path.relpath(os.path.join(root, file), 
                                           os.path.join('heavy_vuln_benchmark', '..')))
    print(f"✅ Generated {py_count-1} Python files and {js_count-1} JS files.")
    print("✅ Created heavy_benchmark.zip")

if __name__ == "__main__":
    create_heavy_benchmark()
