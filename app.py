from flask import Flask, render_template, request, redirect, session, url_for
import hashlib
import hmac
import requests
import os
import sqlite3
import json

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET', 'change-me')

TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')

PLAYEROK_ENDPOINT = 'https://playerok.com/graphql'


# ---- database setup ----
DB_PATH = os.getenv('DB_PATH', 'app.db')
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.execute(
    """CREATE TABLE IF NOT EXISTS users (
            telegram_id TEXT PRIMARY KEY,
            first_name TEXT,
            last_name TEXT,
            username TEXT
        )"""
)
conn.execute(
    """CREATE TABLE IF NOT EXISTS proxies (
            telegram_id TEXT PRIMARY KEY,
            ip TEXT,
            port TEXT,
            username TEXT,
            password TEXT
        )"""
)
conn.execute(
    """CREATE TABLE IF NOT EXISTS playerok_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id TEXT,
            email TEXT,
            cookie TEXT
        )"""
)
conn.commit()


def verify_telegram_auth(data: dict) -> bool:
    """Verify Telegram login using HMAC as described by Telegram."""
    check_hash = data.pop("hash")
    payload = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode()).digest()
    calculated_hash = hmac.new(
        secret_key, payload.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(calculated_hash, check_hash)


def save_user(data: dict) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO users (telegram_id, first_name, last_name, username)"
        " VALUES (?, ?, ?, ?)",
        (
            data.get("id"),
            data.get("first_name"),
            data.get("last_name"),
            data.get("username"),
        ),
    )
    conn.commit()


def get_user_proxy(user_id: str):
    cur = conn.execute(
        "SELECT ip, port, username, password FROM proxies WHERE telegram_id = ?",
        (user_id,),
    )
    row = cur.fetchone()
    return row


def user_has_playerok(user_id: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM playerok_accounts WHERE telegram_id = ? LIMIT 1",
        (user_id,),
    )
    return cur.fetchone() is not None


def get_proxy() -> dict | None:
    """Return a proxies dict for requests if a proxy is configured."""
    user = session.get('telegram_user')
    if not user:
        return None
    row = get_user_proxy(user.get('id'))
    if not row:
        return None
    ip, port, username, password = row
    auth = f"{username}:{password}@" if username and password else ''
    url = f"http://{auth}{ip}:{port}"
    return {"http": url, "https": url}


@app.route('/')
def index():
    user = session.get('telegram_user')
    has_proxy = False
    has_playerok = False
    if user:
        has_proxy = get_user_proxy(user.get('id')) is not None
        has_playerok = user_has_playerok(user.get('id'))
    return render_template(
        'index.html',
        user=user,
        telegram_bot=os.getenv('TELEGRAM_BOT_USERNAME', ''),
        has_proxy=has_proxy,
        has_playerok=has_playerok,
    )


@app.route('/auth/telegram')
def auth_telegram():
    data = dict(request.args)
    if 'hash' not in data:
        return 'Отсутствует hash', 400
    if verify_telegram_auth(data.copy()):
        session['telegram_user'] = data
        save_user(data)
        return redirect(url_for('index'))
    return 'Некорректная авторизация в Telegram', 400


@app.route('/proxy', methods=['GET', 'POST'])
def add_proxy():
    if request.method == 'POST':
        user = session.get('telegram_user')
        if not user:
            return redirect(url_for('index'))
        conn.execute(
            "INSERT OR REPLACE INTO proxies (telegram_id, ip, port, username, password)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                user.get('id'),
                request.form['ip'],
                request.form['port'],
                request.form.get('username', ''),
                request.form.get('password', ''),
            ),
        )
        conn.commit()
        return redirect(url_for('playerok_login'))
    return render_template('proxy.html')


@app.route('/playerok', methods=['GET', 'POST'])
def playerok_login():
    user = session.get('telegram_user')
    if not user:
        return redirect(url_for('index'))
    if not get_user_proxy(user.get('id')):
        return redirect(url_for('add_proxy'))
    if request.method == 'POST':
        email = request.form['email']
        success = request_playerok_code(email)
        if success:
            session['playerok_email'] = email
            return redirect(url_for('playerok_verify'))
        return 'Не удалось отправить код', 400
    return render_template('playerok_login.html')


def request_playerok_code(email: str) -> bool:
    query = 'query getEmailAuthCode($email: String!) { getEmailAuthCode(input: {email: $email}) }'
    variables = {'email': email}
    resp = requests.post(PLAYEROK_ENDPOINT,
                        json={'operationName': 'getEmailAuthCode', 'query': query, 'variables': variables},
                        proxies=get_proxy())
    return resp.ok


@app.route('/playerok/verify', methods=['GET', 'POST'])
def playerok_verify():
    email = session.get('playerok_email')
    user = session.get('telegram_user')
    if not email or not user:
        return redirect(url_for('playerok_login'))
    if request.method == 'POST':
        code = request.form['code']
        session_obj = requests.Session()
        proxy = get_proxy()
        if proxy:
            session_obj.proxies.update(proxy)
        if verify_playerok_code(session_obj, email, code):
            cookie = json.dumps(session_obj.cookies.get_dict())
            conn.execute(
                "INSERT INTO playerok_accounts (telegram_id, email, cookie) VALUES (?, ?, ?)",
                (user.get('id'), email, cookie),
            )
            conn.commit()
            session.pop('playerok_email', None)
            return redirect(url_for('index'))
        return 'Неверный код', 400
    return render_template('playerok_verify.html', email=email)


def verify_playerok_code(sess: requests.Session, email: str, code: str) -> bool:
    query = 'query checkEmailAuthCode($input: CheckEmailAuthCodeInput!) { checkEmailAuthCode(input: $input) { __typename } }'
    variables = {'input': {'email': email, 'code': code}}
    resp = sess.post(PLAYEROK_ENDPOINT,
                    json={'operationName': 'checkEmailAuthCode', 'query': query, 'variables': variables},
                    proxies=get_proxy())
    return resp.ok and 'errors' not in resp.json()


@app.route('/profile')
def profile():
    user = session.get('telegram_user')
    if not user:
        return redirect(url_for('index'))
    accounts = [row[0] for row in conn.execute(
        'SELECT email FROM playerok_accounts WHERE telegram_id = ?',
        (user.get('id'),),
    ).fetchall()]
    return render_template('profile.html', user=user, accounts=accounts)


@app.route('/panel')
def control_panel():
    user = session.get('telegram_user')
    if not user:
        return redirect(url_for('index'))
    cur = conn.execute(
        'SELECT id, email FROM playerok_accounts WHERE telegram_id = ?',
        (user.get('id'),),
    )
    accounts = [{'id': row[0], 'email': row[1]} for row in cur.fetchall()]
    return render_template('panel.html', accounts=accounts)


if __name__ == '__main__':
    app.run(debug=True)
