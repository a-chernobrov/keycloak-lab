#!/usr/bin/env python3
"""Fingerprint Keycloak: сборка/пути, realm'ы, заголовки.

Что проверяем:
  * openid-configuration master-realm (issuer раскрывает базовый URL и префикс путей)
  * префикс путей: современные сборки (Quarkus) — /realms, старые (WildFly) — /auth/realms
  * заголовки ответа (Server и т.п.)
  * доступность admin-консоли
  * хэш ассетов консоли (resources/<hash>)

Запуск:
  python3 fingerprint.py [--url http://keycloak.127.0.0.1.nip.io:8080]
"""
import argparse
import json
import os
import re
import urllib.request
import urllib.error


def fetch(url, method="GET", allow_redirects=True):
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "recon"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "ignore")
    except Exception as e:
        return None, {}, str(e)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=os.environ.get("KC_URL", "http://keycloak.127.0.0.1.nip.io:8080"))
    a = p.parse_args()
    base = a.url.rstrip("/")

    print(f"[*] Target: {base}\n")

    # 1) openid-configuration master realm
    st, hd, body = fetch(f"{base}/realms/master/.well-known/openid-configuration")
    print(f"[1] /realms/master/.well-known/openid-configuration -> {st}")
    if st == 200:
        cfg = json.loads(body)
        print(f"    issuer: {cfg.get('issuer')}")
        for k in ("authorization_endpoint", "token_endpoint", "registration_endpoint",
                  "end_session_endpoint", "device_authorization_endpoint"):
            if cfg.get(k):
                print(f"    {k}: {cfg[k]}")
        # признак сборки по префиксу путей
        build = "WildFly (/auth)" if "/auth/realms/" in cfg.get("issuer", "") else "Quarkus (/realms)"
        print(f"    => build: {build}")

    # 2) старый префикс /auth/realms
    st_auth, _, _ = fetch(f"{base}/auth/realms/master/.well-known/openid-configuration")
    print(f"\n[2] /auth/realms/master/.well-known/openid-configuration -> {st_auth}"
          f"  ({'нет /auth-префикса => Quarkus' if st_auth == 404 else 'presence'})")

    # 3) заголовки корня и admin-консоли
    st_root, hd_root, _ = fetch(f"{base}/")
    print(f"\n[3] GET / -> {st_root}")
    for k in ("Server", "X-Powered-By", "Content-Type"):
        if hd_root.get(k):
            print(f"    {k}: {hd_root[k]}")

    # 4) admin console
    st_con, _, body_con = fetch(f"{base}/admin/master/console/")
    print(f"\n[4] /admin/master/console/ -> {st_con}")
    m = re.search(r'/resources/[^"\']+', body_con or "")
    if m:
        print(f"    asset: {m.group(0)}")
    m2 = re.search(r'"(?:version|resourceVersion)"\s*:\s*"([^"]+)"', body_con or "")
    if m2:
        print(f"    console version: {m2.group(1)}")

    # 5) realm enumeration по словарю
    print("\n[5] realm probe:")
    for r in ("master", "vulnerable", "production", "admin", "staging", "dev"):
        st_r, _, _ = fetch(f"{base}/realms/{r}/.well-known/openid-configuration")
        print(f"    {r:12s} {st_r}")


if __name__ == "__main__":
    main()