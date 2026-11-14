#!/usr/bin/env python3
"""Энумерация realm'ов по словарю через openid-configuration.

200 -> realm существует, 404 -> нет.

Пример:
  python3 enum_realms.py --url http://keycloak.127.0.0.1.nip.io:8080 --words master vulnerable production admin
"""
import argparse
import os
import urllib.request
import urllib.error

WORDS = ["master", "vulnerable", "production", "internal", "staging", "dev", "test"]


def probe(url, realm):
    u = f"{url}/realms/{realm}/.well-known/openid-configuration"
    try:
        with urllib.request.urlopen(u, timeout=8) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return "ERR"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=os.environ.get("KC_URL", "http://keycloak.127.0.0.1.nip.io:8080"))
    p.add_argument("--words", nargs="*", default=WORDS)
    a = p.parse_args()

    print(f"[*] Enumeration against {a.url}")
    for w in a.words:
        code = probe(a.url, w)
        mark = "EXISTS" if code == 200 else "      "
        print(f"    [{mark}] {w:12s} {code}")


if __name__ == "__main__":
    main()