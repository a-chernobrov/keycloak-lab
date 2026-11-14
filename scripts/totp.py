#!/usr/bin/env python3
"""Генератор TOTP-кодов (RFC 6238). Без внешних зависимостей.

ВАЖНО про Keycloak: сервер валидирует OTP как
    TimeBasedOTP.validateTOTP(token, secret.getBytes())
т.е. ключом HMAC служат СЫРЫЕ байты строки секрета, а не её base32-декод.
Поэтому по умолчанию key_encoding="raw" (совместимо с Keycloak).
Для стандартных аутентификаторов (Google Authenticator) используйте
key_encoding="base32".

CLI:
    python3 totp.py JBSWY3DPEHPK3PXP
    python3 totp.py JBSWY3DPEHPK3PXP --base32 --remain
"""
import base64
import hashlib
import hmac
import struct
import sys
import time

ALGOS = {"HmacSHA1": hashlib.sha1, "HmacSHA256": hashlib.sha256, "HmacSHA512": hashlib.sha512}


def _key(secret: str, encoding: str) -> bytes:
    if encoding == "base32":
        s = secret.strip().replace(" ", "").upper()
        s += "=" * (-len(s) % 8)
        return base64.b32decode(s, casefold=True)
    return secret.encode()  # raw — так делает Keycloak


def totp(secret: str, digits: int = 6, period: int = 30,
         at: float | None = None, algorithm: str = "HmacSHA1",
         key_encoding: str = "raw") -> str:
    """TOTP-код на момент `at` (по умолчанию — сейчас)."""
    counter = int((at if at is not None else time.time()) // period)
    key = _key(secret, key_encoding)
    h = hmac.new(key, struct.pack(">Q", counter), ALGOS[algorithm]).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def seconds_left(period: int = 30, at: float | None = None) -> int:
    at = at if at is not None else time.time()
    return period - int(at % period)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    secret = sys.argv[1]
    enc = "base32" if "--base32" in sys.argv else "raw"
    code = totp(secret, key_encoding=enc)
    print(f"{code} (осталось {seconds_left()}s)" if "--remain" in sys.argv else code)