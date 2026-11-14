#!/usr/bin/env python3
"""Наполнение OTP-креденшелов пользователей через Admin REST API.

Два режима:
  --shared JBSWY3DPEHPK3PXP   всем пользователям ОДИН и тот же TOTP-секрет  (УЯЗВИМО)
  --unique                    каждому пользователю случайный TOTP-секрет     (ИСПРАВЛЕНО)

Реализовано через POST .../partialImport: эндпоинт
POST /users/{id}/credentials в этой сборке недоступен (404), а partialImport работает.
Пароли задаются отдельно, т.к. partialImport c OVERWRITE пересоздаёт
представление пользователя целиком.

Примеры:
  python3 seed_totp.py --users alice mallory --shared JBSWY3DPEHPK3PXP
  python3 seed_totp.py --users alice mallory --unique
"""
import argparse
import base64
import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error

DEFAULT_URL = os.environ.get("KC_URL", "http://keycloak.127.0.0.1.nip.io:8080")
# Пароли лабораторных юзеров (совпадают с realm-JSON)
DEFAULT_PASSWORDS = {"alice": "Passw0rd!", "mallory": "Mall0ry!"}


def http(method, url, data=None, headers=None, form=False):
    body = None
    headers = dict(headers or {})
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
    headers["Accept"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def admin_token(url, user, password):
    status, data = http(
        "POST", f"{url}/realms/master/protocol/openid-connect/token",
        {"grant_type": "password", "client_id": "admin-cli",
         "username": user, "password": password},
        form=True,
    )
    if status != 200:
        sys.exit(f"Не получил admin-токен ({status}): {data}")
    return data["access_token"]


def otp_credential(secret):
    return {
        "type": "otp",
        "userLabel": "totp",
        "secretData": json.dumps({"value": secret}),
        "credentialData": json.dumps(
            {"subType": "totp", "digits": 6, "period": 30, "algorithm": "HmacSHA1"}),
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=DEFAULT_URL, help="база Keycloak")
    p.add_argument("--realm", default="vulnerable")
    p.add_argument("--admin-user", default="admin")
    p.add_argument("--admin-pass", default="admin")
    p.add_argument("--users", nargs="+", required=True)
    p.add_argument("--passwords", nargs="*", default=[],
                   help="переопределить пароли: alice=Passw0rd! mallory=Mall0ry!")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--shared", help="один общий base32-секрет для всех")
    g.add_argument("--unique", action="store_true", help="уникальный секрет на пользователя")
    a = p.parse_args()

    passwords = dict(DEFAULT_PASSWORDS)
    for kv in a.passwords:
        k, _, v = kv.partition("=")
        passwords[k] = v

    token = admin_token(a.url, a.admin_user, a.admin_pass)

    users_repr = []
    for u in a.users:
        secret = a.shared if a.shared else base64.b32encode(os.urandom(10)).decode().rstrip("=")
        creds = []
        if u in passwords:
            creds.append({"type": "password", "value": passwords[u], "temporary": False})
        creds.append(otp_credential(secret))
        users_repr.append({
            "username": u,
            "enabled": True,
            "email": f"{u}@lab.local",
            "emailVerified": True,
            # firstName/lastName обязательны для профиля юзера в Keycloak 26,
            # иначе login падает с "Account is not fully set up"
            "firstName": u.capitalize(),
            "lastName": "User",
            "credentials": creds,
        })
        print(f"{u:12s} -> OTP secret = {secret}")

    status, resp = http(
        "POST", f"{a.url}/admin/realms/{a.realm}/partialImport",
        {"ifResourceExists": "OVERWRITE", "users": users_repr},
        headers={"Authorization": f"Bearer {token}"},
    )
    if status not in (200, 201):
        sys.exit(f"partialImport не удался ({status}): {resp}")
    print(f"[+] {resp}")


if __name__ == "__main__":
    main()