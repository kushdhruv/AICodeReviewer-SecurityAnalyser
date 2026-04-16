
import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    # SSRF vulnerability
    resp = requests.get(url) 
    return resp.text
