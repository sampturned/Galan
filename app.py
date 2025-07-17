from flask import Flask, render_template, request, redirect, session, url_for
import hashlib
import requests
import os

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET', 'change-me')

TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')

PLAYEROK_ENDPOINT = 'https://playerok.com/graphql'


def verify_telegram_auth(data: dict) -> bool:
    """Verify Telegram login using the hash and bot token."""
    check_hash = data.pop('hash')
    payload = '\n'.join([f'{k}={v}' for k, v in sorted(data.items())])
    secret_key = hashlib.sha256(TELEGRAM_BOT_TOKEN.encode()).digest()
    h = hashlib.sha256()
    h.update(payload.encode())
    h.update(secret_key)
    calculated_hash = h.hexdigest()
    return calculated_hash == check_hash


def get_proxy() -> dict | None:
    """Return a proxies dict for requests if a proxy is configured."""
    p = session.get('proxy')
    if not p:
        return None
    auth = f"{p['username']}:{p['password']}@" if p['username'] and p['password'] else ''
    url = f"http://{auth}{p['ip']}:{p['port']}"
    return {'http': url, 'https': url}


@app.route('/')
def index():
    user = session.get('telegram_user')
    return render_template('index.html', user=user, telegram_bot=os.getenv('TELEGRAM_BOT_USERNAME', ''))


@app.route('/auth/telegram')
def auth_telegram():
    data = dict(request.args)
    if 'hash' not in data:
        return 'Отсутствует hash', 400
    if verify_telegram_auth(data.copy()):
        session['telegram_user'] = data
        return redirect(url_for('index'))
    return 'Некорректная авторизация в Telegram', 400


@app.route('/proxy', methods=['GET', 'POST'])
def add_proxy():
    if request.method == 'POST':
        session['proxy'] = {
            'ip': request.form['ip'],
            'port': request.form['port'],
            'username': request.form.get('username', ''),
            'password': request.form.get('password', '')
        }
        return redirect(url_for('playerok_login'))
    return render_template('proxy.html')


@app.route('/playerok', methods=['GET', 'POST'])
def playerok_login():
    if 'proxy' not in session:
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
    if not email:
        return redirect(url_for('playerok_login'))
    if request.method == 'POST':
        code = request.form['code']
        session_obj = requests.Session()
        proxy = get_proxy()
        if proxy:
            session_obj.proxies.update(proxy)
        if verify_playerok_code(session_obj, email, code):
            session['playerok_cookie'] = session_obj.cookies.get_dict()
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


if __name__ == '__main__':
    app.run(debug=True)
