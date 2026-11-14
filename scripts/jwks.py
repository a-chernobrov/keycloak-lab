#!/usr/bin/env python3
"""Преобразование JWK (RSA) в PEM — только stdlib, без сторонних библиотек.

Нужно, чтобы одинаково (детерминированно) получить PEM публичного ключа
realm'а из JWKS. Используется и атакующим скриптом, и уязвимым resource server:
при RS256->HS256 confusion HMAC-ключом служат байты именно этого PEM.

API:
    pem = jwk_rsa_to_pem({"kty":"RSA","n":"...","e":"..."})
    pem = jwks_to_pem(jwks)   # первый RSA-ключ
"""
import base64


def _b64url(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(content)) + content


def _int(data: bytes) -> bytes:
    data = data.lstrip(b"\x00") or b"\x00"
    if data[0] & 0x80:
        data = b"\x00" + data
    return _tlv(0x02, data)


def _seq(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def jwk_rsa_to_pem(jwk: dict) -> str:
    n = int.from_bytes(_b64url(jwk["n"]), "big")
    e = int.from_bytes(_b64url(jwk["e"]), "big")
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, "big")

    rsa_oid = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
    rsapub = _seq(_int(n_bytes), _int(e_bytes))
    spki = _seq(_seq(_tlv(0x06, rsa_oid), _tlv(0x05, b"")), _tlv(0x03, b"\x00" + rsapub))

    b64 = base64.b64encode(spki).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def jwks_to_pem(jwks: dict) -> str:
    for key in jwks.get("keys", []):
        if key.get("kty") == "RSA":
            return jwk_rsa_to_pem(key)
    raise ValueError("no RSA key in JWKS")