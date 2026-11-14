#!/usr/bin/env python3
"""Энумерация realm'ов и клиентов.

Realm — по словарю через openid-configuration (200 = есть, 404 = нет).
Client — error-based через authorization endpoint: Keycloak по-разному отвечает
на несуществующий `client_id` ("Client not found") и на существующий (страница логина
или ошибка redirect_uri) — это и есть oracle.

Запуск:
  python3 enum_clients.py --url http://keycloak.127.0.0.1.nip.io:8080 --realm vulnerable
"""
import argparse
import os
import urllib.parse
import urllib.request
import urllib.error

REALM_WORDS = ["master", "vulnerable", "production", "internal", "staging", "dev", "test", "admin"]
CLIENT_WORDS = [
    "sp-app", "direct-grant", "public-spa",
    "account", "account-console", "admin-cli", "broker",
    "security-admin-console", "realm-management",
]


def get(url):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "recon"}), timeout=8) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")
    except Exception as e:
        return None, str(e)


def enum_realms(base):
    print("[*] realm enumeration")
    for r in REALM_WORDS:
        st, _ = get(f"{base}/realms/{r}/.well-known/openid-configuration")
        print(f"    [{'EXISTS' if st == 200 else '      '}] {r:12s} {st}")


def client_exists(base, realm, cid):
    q = urllib.parse.urlencode({
        "client_id": cid, "response_type": "code",
        "redirect_uri": os.environ.get("SP_URL", "http://app.127.0.0.1.nip.io:8088") + "/callback",
        "scope": "openid",
    })
    st, body = get(f"{base}/realms/{realm}/protocol/openid-connect/auth?{q}")
    if st is None:
        return None, ""
    low = body.lower()
    if "client not found" in low:
        return False, "client not found"
    if "invalid parameter: redirect_uri" in low:
        return True, "exists (redirect_uri rejected)"
    if st in (200, 302):
        return True, "exists (login/redirect)"
    return None, f"unclear ({st})"


def enum_clients(base, realm):
    print(f"\n[*] client enumeration in realm '{realm}'")
    for cid in CLIENT_WORDS:
        ok, note = client_exists(base, realm, cid)
        mark = "EXISTS" if ok else ("      " if ok is False else "  ?   ")
        print(f"    [{mark}] {cid:22s} {note}")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=os.environ.get("KC_URL", "http://keycloak.127.0.0.1.nip.io:8080"))
    p.add_argument("--realm", default="vulnerable")
    a = p.parse_args()
    base = a.url.rstrip("/")
    enum_realms(base)
    enum_clients(base, a.realm)


if __name__ == "__main__":
    main()