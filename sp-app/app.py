"""Простое SP-приложение (relying party) за Keycloak.

Никакого серьёзного функционала: цель — сходить в Keycloak по OIDC
и показать, что именно вернул identity provider. Всё, что приложение
"умеет", — это логин/колбэк/показ claims/логаут.
"""
import base64
import json
import os
from urllib.parse import urlencode

import requests
from flask import Flask, redirect, request, session, jsonify

PUBLIC = os.environ["KC_PUBLIC_URL"].rstrip("/")       # для браузера (публичный URL)
INTERNAL = os.environ["KC_INTERNAL_URL"].rstrip("/")   # для бэкенд-вызовов (сеть docker)
REALM = os.environ["KC_REALM"]
CLIENT_ID = os.environ["KC_CLIENT_ID"]
CLIENT_SECRET = os.environ["KC_CLIENT_SECRET"]
REDIRECT_URI = os.environ["REDIRECT_URI"]

AUTH_EP = f"{PUBLIC}/realms/{REALM}/protocol/openid-connect/auth"
TOKEN_EP = f"{INTERNAL}/realms/{REALM}/protocol/openid-connect/token"
USERINFO_EP = f"{INTERNAL}/realms/{REALM}/protocol/openid-connect/userinfo"
LOGOUT_EP = f"{PUBLIC}/realms/{REALM}/protocol/openid-connect/logout"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev")


def decode_jwt(token):
    """Разбор JWT без проверки подписи — только чтобы посмотреть claims."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


@app.route("/")
def index():
    user = session.get("user")
    if user:
        body = f"<p>Вы вошли как <b>{user.get('preferred_username')}</b>.</p>"
        body += '<p><a href="/profile">profile</a> | <a href="/logout">logout</a></p>'
    else:
        body = '<p><a href="/login">Войти через Keycloak</a></p>'
    return f"<h3>SP-App</h3>{body}<p>realm: {REALM}, client: {CLIENT_ID}</p>"


@app.route("/login")
def login():
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": REDIRECT_URI,
        "state": os.urandom(8).hex(),
    }
    session["state"] = params["state"]
    return redirect(f"{AUTH_EP}?{urlencode(params)}")


@app.route("/callback")
def callback():
    if request.args.get("state") != session.get("state"):
        return "state mismatch", 400
    if "error" in request.args:
        return jsonify(request.args), 400

    resp = requests.post(
        TOKEN_EP,
        data={
            "grant_type": "authorization_code",
            "code": request.args["code"],
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        timeout=10,
    )
    tokens = resp.json()
    session["tokens"] = tokens
    session["user"] = decode_jwt(tokens.get("access_token", "")) or {}
    return redirect("/profile")


@app.route("/profile")
def profile():
    tokens = session.get("tokens")
    if not tokens:
        return redirect("/login")
    return jsonify({
        "id_token_claims": decode_jwt(tokens.get("id_token", "")),
        "access_token_claims": decode_jwt(tokens.get("access_token", "")),
        "expires_in": tokens.get("expires_in"),
        "has_refresh_token": "refresh_token" in tokens,
    })


@app.route("/logout")
def logout():
    session.clear()
    return redirect(LOGOUT_EP)


@app.route("/go")
def go():
    """Намеренно «дырявый» редирект: используется как шаг эксфильтрации в модуле 03."""
    return redirect(request.args.get("to", "/"))


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)