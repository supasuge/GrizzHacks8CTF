import os
import secrets
from flask import Flask, render_template, request, jsonify, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

FLAG_FILE = 'flag.txt'

def get_flag():
    try:
        with open(FLAG_FILE, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return 'GrizzCTF{flag_not_found}'

@app.route('/')
def home():
    session['token'] = secrets.token_hex(32)
    return render_template('index.html', token=session['token'])

@app.route('/api/flag', methods=['POST'])
def api_flag():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request'}), 400

    token = data.get('token')
    if not token:
        return jsonify({'error': 'Missing token'}), 400

    if 'token' not in session or token != session['token']:
        return jsonify({'error': 'Invalid token'}), 403

    return jsonify({'flag': get_flag()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
