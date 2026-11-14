#!/usr/bin/env python3
"""Модуль 08: сессии, refresh-токены и logout.

Проверяем:
  1) ротацию refresh token (revokeRefreshToken) — можно ли переиспользовать старый RT;
  2) что происходит после logout: инвалидируется ли RT;
  3) «жив ли» уже выданный access token после logout (JWT stateless, RS не проверяет revocation).

Пример:
  python3 session_demo.py
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from totp import totp


def post(url, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            raw = json.loads(raw)
        except Exception:
            pass
        return e.code, raw


def get_rs(rs, token):
    req = urllib.request.Request(f"{rs}/api/me", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=os.environ.get("KC_URL", "http://keycloak.127.0.0.1.nip.io:8080"))
    p.add_argument("--realm", default="vulnerable")
    p.add_argument("--client-id", default="direct-grant")
    p.add_argument("--client-secret", default="direct-grant-secret")
    p.add_argument("--username", default="alice")
    p.add_argument("--password", default="Passw0rd!")
    p.add_argument("--totp-secret", default="JBSWY3DPEHPK3PXP")
    p.add_argument("--rs", default=os.environ.get("RS_URL", "http://localhost:8090"))
    a = p.parse_args()
    base = a.url.rstrip("/")
    tok_ep = f"{base}/realms/{a.realm}/protocol/openid-connect/token"
    logout_ep = f"{base}/realms/{a.realm}/protocol/openid-connect/logout"

    # 1) логин
    st, toks = post(tok_ep, {"grant_type": "password", "client_id": a.client_id,
                             "client_secret": a.client_secret, "username": a.username,
                             "password": a.password, "totp": totp(a.totp_secret)})
    if st != 200:
        sys.exit(f"login failed: {st} {toks}")
    at, rt = toks["access_token"], toks["refresh_token"]
    print(f"[1] login OK (access_token, refresh_token)")

    # 2) ротация refresh token: переиспользуем СТАРЫЙ RT повторно
    st1, r1 = post(tok_ep, {"grant_type": "refresh_token", "client_id": a.client_id,
                            "client_secret": a.client_secret, "refresh_token": rt})
    print(f"[2] refresh #1 со старым RT -> {st1}")
    st2, r2 = post(tok_ep, {"grant_type": "refresh_token", "client_id": a.client_id,
                            "client_secret": a.client_secret, "refresh_token": rt})
    if st2 == 200:
        print(f"    refresh #2 тем ЖЕ (старым) RT -> {st2}: старый RT остаётся валиден "
              f"-> revokeRefreshToken выключен [риск]")
    else:
        print(f"    refresh #2 тем ЖЕ (старым) RT -> {st2}: старый RT инвалидирован [ok]")

    # 3) logout
    cur_rt = r1.get("refresh_token", rt) if st1 == 200 and isinstance(r1, dict) else rt
    st, body = post(logout_ep, {"client_id": a.client_id, "client_secret": a.client_secret,
                                "refresh_token": cur_rt})
    print(f"[3] logout -> {st}")

    # 4) refresh после logout
    st, body = post(tok_ep, {"grant_type": "refresh_token", "client_id": a.client_id,
                             "client_secret": a.client_secret, "refresh_token": cur_rt})
    print(f"[4] refresh после logout -> {st} {str(body)[:80]}")

    # 5) старый access token всё ещё работает на RS
    code = get_rs(a.rs, at)
    print(f"[5] RS {a.rs}/api/me старым access_token после logout -> {code}"
          f"  ({'ещё валиден' if code == 200 else 'отклонён'})")


if __name__ == "__main__":
    sys.exit(main())