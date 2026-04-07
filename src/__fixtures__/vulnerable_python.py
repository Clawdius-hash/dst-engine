# Deliberately vulnerable Python code for DST validation
# Each function has a KNOWN vulnerability mapped to a CWE

import os
import sqlite3
import subprocess
import pickle
import yaml
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)
db = sqlite3.connect('app.db')

# CWE-89: SQL Injection
@app.route('/users/search')
def search_users():
    username = request.args.get('username')
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return str(cursor.fetchall())

# CWE-78: OS Command Injection
@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = os.system("ping -c 1 " + host)
    return str(result)

# CWE-78: Command injection via subprocess
@app.route('/convert')
def convert():
    filename = request.args.get('file')
    subprocess.call("ffmpeg -i " + filename + " output.mp4", shell=True)
    return "Converting..."

# CWE-79: XSS via template injection
@app.route('/welcome')
def welcome():
    name = request.args.get('name')
    return render_template_string('<h1>Welcome, ' + name + '!</h1>')

# CWE-502: Unsafe deserialization
@app.route('/load', methods=['POST'])
def load_data():
    data = request.get_data()
    obj = pickle.loads(data)
    return str(obj)

# CWE-502: Unsafe YAML deserialization
@app.route('/config', methods=['POST'])
def load_config():
    content = request.get_data().decode()
    config = yaml.load(content)
    return str(config)

# CWE-918: SSRF
@app.route('/proxy')
def proxy():
    import urllib.request
    url = request.args.get('url')
    response = urllib.request.urlopen(url)
    return response.read()

# CWE-22: Path traversal
@app.route('/read')
def read_file():
    filename = request.args.get('path')
    with open(filename, 'r') as f:
        return f.read()

# CWE-798: Hardcoded credentials
DB_PASSWORD = "SuperSecretPassword123"
API_KEY = "sk_live_abc123def456"

# CWE-94: Code injection via eval
@app.route('/calc')
def calculator():
    expr = request.args.get('expr')
    result = eval(expr)
    return str(result)

# CWE-200: Information exposure
@app.route('/error')
def trigger_error():
    try:
        1/0
    except Exception as e:
        import traceback
        return traceback.format_exc()

if __name__ == '__main__':
    app.run(debug=True)
