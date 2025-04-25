#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FAAST - Aplicativo Flask Vulnerável para Testes
-----------------------------------------------
Este aplicativo contém diversas vulnerabilidades intencionais
para teste do sistema FAAST.
"""

import os
import sqlite3
import random
import pickle
import base64
import subprocess
from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "super_secret_key_for_testing_only"
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
app.config['DATABASE'] = 'database.db'

# Assegura que o diretório de upload existe
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Inicializa o banco de dados SQLite
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Inserir usuários de exemplo se não existirem
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      ("admin", "admin123", "admin"))
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                      ("user", "password123", "user"))
    
    conn.commit()
    conn.close()

# Inicializa o banco de dados na inicialização
with app.app_context():
    init_db()


# Rotas da aplicação
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Vulnerabilidade: Injeção SQL (SQLi)
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            session['role'] = user[3]  # role
            return redirect(url_for('dashboard'))
        else:
            error = 'Credenciais inválidas. Tente novamente.'
    
    return render_template('login.html', error=error)


@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session.get('username'), role=session.get('role'))


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    
    # Vulnerabilidade: Cross-Site Scripting (XSS)
    results = []
    if query:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute("SELECT content FROM messages WHERE content LIKE ?", (f"%{query}%",))
        results = [row[0] for row in cursor.fetchall()]
        conn.close()
    
    return render_template('search.html', query=query, results=results)


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Vulnerabilidade: Armazenamento inseguro de arquivos
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file.filename:
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                return render_template('profile.html', message=f"Avatar salvo como {filename}")
    
    return render_template('profile.html')


@app.route('/admin')
def admin():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return "Acesso não autorizado", 403
    
    # Vulnerabilidade: Acesso inseguro a arquivos
    log_file = request.args.get('log', 'app.log')
    log_path = os.path.join('/var/log/', log_file)
    
    try:
        with open(log_path, 'r') as f:
            logs = f.read()
    except Exception as e:
        logs = f"Erro ao ler o arquivo: {str(e)}"
    
    return render_template('admin.html', logs=logs)


@app.route('/exec', methods=['POST'])
def execute_command():
    if not session.get('logged_in') or session.get('role') != 'admin':
        return jsonify({'error': 'Acesso não autorizado'}), 403
    
    # Vulnerabilidade: Execução de comandos (RCE)
    command = request.form.get('command', '')
    
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return jsonify({'output': output.decode('utf-8')})
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.output.decode('utf-8')})


@app.route('/api/data')
def api_data():
    # Vulnerabilidade: Server-Side Request Forgery (SSRF)
    url = request.args.get('url', 'http://localhost/default.json')
    
    try:
        import urllib.request
        response = urllib.request.urlopen(url)
        data = response.read().decode('utf-8')
        return data
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/notes', methods=['GET', 'POST'])
def notes():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        note_content = request.form.get('content', '')
        
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        
        # Obtém ID do usuário
        cursor.execute("SELECT id FROM users WHERE username = ?", (session.get('username'),))
        user_id = cursor.fetchone()[0]
        
        # Salva a nota
        cursor.execute("INSERT INTO messages (user_id, content) VALUES (?, ?)", 
                      (user_id, note_content))
        conn.commit()
        conn.close()
        
        return redirect(url_for('notes'))
    
    # Busca notas do usuário
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ?", (session.get('username'),))
    user_id = cursor.fetchone()[0]
    
    cursor.execute("SELECT content, created_at FROM messages WHERE user_id = ? ORDER BY created_at DESC", 
                  (user_id,))
    notes_list = cursor.fetchall()
    conn.close()
    
    return render_template('notes.html', notes=notes_list)


@app.route('/api/store', methods=['POST'])
def store_object():
    if not session.get('logged_in'):
        return jsonify({'error': 'Acesso não autorizado'}), 403
    
    # Vulnerabilidade: Desserialização insegura (Pickle)
    data = request.form.get('data', '')
    
    try:
        decoded_data = base64.b64decode(data)
        # Desserialização insegura
        object_data = pickle.loads(decoded_data)
        return jsonify({'success': True, 'data': str(object_data)})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/api/token')
def generate_token():
    # Vulnerabilidade: Geração de tokens previsíveis
    username = request.args.get('username', '')
    timestamp = int(os.getenv('TIMESTAMP', '1234567890'))  # Valor fixo para testes
    
    # Gerador pseudoaleatório com seed previsível
    random.seed(timestamp)
    token_value = random.randint(10000, 99999)
    
    token = f"{username}:{token_value}"
    encoded_token = base64.b64encode(token.encode()).decode()
    
    return jsonify({'token': encoded_token})


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')