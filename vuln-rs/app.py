"""Уязвимый resource server (RS) для модуля 05.

Намеренно «плохая» проверка access-токена Keycloak:
  * принимает alg=none (без подписи);
  * при alg=HS256 проверяет HMAC, используя ПУБЛИЧНЫЙ ключ realm'а (PEM) как секрет
    -> классическая RS256 -> HS256 confusion;
  * НЕ проверяет iss/aud/exp.

Режим сравнения: MODE=strict — принимает только RS256 и проверяет iss/aud/exp.

Эндпоинты:
  GET /api/me      — вернёт claims, если токен «валиден» по правилам выше
  GET /api/admin   — «привилегированный» ресурс (демонстрация impact)
  GET /health
"""
import base64
import hashlib
import hmac
import json
import os

import requests
from flask import Flask, jsonify, request

from jwks import jwks_to_pem

KC_JWKS_URL = os.environ["KC_JWKS_URL"]
KC_ISSUER = os.environ.get("KC_ISSUER", "")
MODE = os.environ.get("MODE", "vuln")  # vuln | strict

app = Flask(__name__)
_jwks_cache = {}


def get_jwks():
    if "v" not in _jwks_cache:
        _jwks_cache["v"] = requests.get(KC_JWKS_URL, timeout=5).json()
    return _jwks_cache["v"]


def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def rsa_verify_rs256(jwks: dict, signing_input: bytes, signature: bytes) -> bool:
    """Проверка RS256 (PKCS#1 v1.5 + SHA-256) на чистом Python."""
    key = next(k for k in jwks["keys"] if k.get("kty") == "RSA")
    n = int.from_bytes(b64url_decode(key["n"]), "big")
    e = int.from_bytes(b64url_decode(key["e"]), "big")
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    digest = hashlib.sha256(signing_input).digest()
    # DigestInfo префикс для SHA-256
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    expected = b"\x00\x01" + b"\xff" * (k - 3 - len(prefix) - len(digest)) + b"\x00" + prefix + digest
    return hmac.compare_digest(em, expected)


def verify_token(token: str):
    """Возвращает (payload, reason)."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return None, "malformed token"
    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = b64url_decode(sig_b64) if sig_b64 else b""
    alg = header.get("alg", "")
    jwks = get_jwks()

    if MODE == "strict":
        if alg != "RS256":
            return None, f"alg {alg} not allowed (strict)"
        if not rsa_verify_rs256(jwks, signing_input, signature):
            return None, "bad signature"
        if KC_ISSUER and payload.get("iss") != KC_ISSUER:
            return None, "bad issuer"
        return payload, "ok (RS256 verified)"

    # --- VULNERABLE MODE ---
    if alg == "none":
        return payload, "accepted alg=none (NOT VERIFIED)"
    if alg == "HS256":
        secret = jwks_to_pem(jwks).encode()  # публичный ключ как HMAC-секрет
        expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
        if hmac.compare_digest(expected, signature):
            return payload, "accepted HS256 signed with PUBLIC key (confusion)"
        return None, "bad HS256 signature"
    if alg == "RS256":
        if rsa_verify_rs256(jwks, signing_input, signature):
            return payload, "ok (RS256 verified)"
        return None, "bad RS256 signature"
    return None, f"unsupported alg {alg}"


def _auth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, ("missing bearer token", 401)
    payload, reason = verify_token(auth[7:])
    if payload is None:
        return None, (reason, 401)
    return (payload, reason), None


@app.route("/api/me")
def me():
    res, err = _auth()
    if err:
        return jsonify({"error": err[0]}), err[1]
    payload, reason = res
    return jsonify({"note": reason, "preferred_username": payload.get("preferred_username"),
                    "sub": payload.get("sub"), "claims": payload})


@app.route("/api/admin")
def admin():
    res, err = _auth()
    if err:
        return jsonify({"error": err[0]}), err[1]
    payload, reason = res
    # «привилегированный» ресурс — в лабе просто проверяем наличие роли
    roles = payload.get("realm_access", {}).get("roles", [])
    if "admin" not in roles:
        return jsonify({"error": "not admin", "roles": roles}), 403
    return jsonify({"note": reason, "message": "SECRET ADMIN DATA", "roles": roles})


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090)