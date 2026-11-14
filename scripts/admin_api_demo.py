#!/usr/bin/env python3
"""Модуль 07: Admin REST API, service accounts и избыточные роли.

Сценарий:
  1) admin API без токена -> 401;
  2) создаём service-account клиента и выдаём ему realm-admin (избыточно);
  3) берём client_credentials-токен и ходим в admin API -> полный доступ;
  4) сравниваем с клиентом без ролей -> 403.

Пример:
  python3 admin_api_demo.py
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

MASTER = os.environ.get("KC_URL", "http://keycloak.127.0.0.1.nip.io:8080")


def http(method, url, data=None, token=None, form=False):
    headers = {"Accept": "application/json"}
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            raw = json.loads(raw)
        except Exception:
            pass
        return e.code, raw


def ensure_sa_client(base, realm, token, client_id, secret, roles, rm_id):
    # удалить, если уже есть
    st, clients = http("GET", f"{base}/admin/realms/{realm}/clients?clientId={client_id}", token=token)
    for c in clients or []:
        http("DELETE", f"{base}/admin/realms/{realm}/clients/{c['id']}", token=token)
    http("POST", f"{base}/admin/realms/{realm}/clients", {
        "clientId": client_id, "enabled": True, "protocol": "openid-connect",
        "publicClient": False, "secret": secret,
        "serviceAccountsEnabled": True, "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
    }, token=token)
    _, clients = http("GET", f"{base}/admin/realms/{realm}/clients?clientId={client_id}", token=token)
    cid = clients[0]["id"]
    _, sa = http("GET", f"{base}/admin/realms/{realm}/clients/{cid}/service-account-user", token=token)
    if roles:
        http("POST", f"{base}/admin/realms/{realm}/users/{sa['id']}/role-mappings/clients/{rm_id}",
             roles, token=token)
    return sa["id"]


def client_token(base, realm, client_id, secret):
    st, data = http("POST", f"{base}/realms/{realm}/protocol/openid-connect/token",
                    {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret},
                    form=True)
    return data.get("access_token") if st == 200 else None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", default=MASTER)
    p.add_argument("--realm", default="vulnerable")
    p.add_argument("--admin-user", default="admin")
    p.add_argument("--admin-pass", default="admin")
    a = p.parse_args()
    base, realm = a.base.rstrip("/"), a.realm

    print("=== 1) admin API без токена ===")
    st, body = http("GET", f"{base}/admin/realms/{realm}/users")
    print(f"    GET /admin/realms/{realm}/users -> {st} {str(body)[:80]}")

    # admin-токен (master)
    _, tok = http("POST", f"{base}/realms/master/protocol/openid-connect/token",
                  {"grant_type": "password", "client_id": "admin-cli",
                   "username": a.admin_user, "password": a.admin_pass}, form=True)
    token = tok["access_token"]

    # realm-management клиент и роль realm-admin
    _, rm = http("GET", f"{base}/admin/realms/{realm}/clients?clientId=realm-management", token=token)
    rm_id = rm[0]["id"]
    _, rm_roles = http("GET", f"{base}/admin/realms/{realm}/clients/{rm_id}/roles", token=token)
    realm_admin = next(r for r in rm_roles if r["name"] == "realm-admin")

    print("\n=== 2) service account с избыточной ролью realm-admin ===")
    sa = ensure_sa_client(base, realm, token, "svc-overprivileged", "svc-secret", [realm_admin], rm_id)
    print("    создан клиент svc-overprivileged, роль realm-admin выдана сервис-аккаунту")

    print("\n=== 3) client_credentials-токен -> admin API ===")
    svc_token = client_token(base, realm, "svc-overprivileged", "svc-secret")
    st, body = http("GET", f"{base}/admin/realms/{realm}/users", token=svc_token)
    print(f"    GET /admin/realms/{realm}/users -> {st} (users={len(body) if isinstance(body, list) else '?'})")

    print("\n=== 4) сравнение: service account БЕЗ ролей ===")
    ensure_sa_client(base, realm, token, "svc-noroles", "svc2-secret", [], rm_id)
    svc2 = client_token(base, realm, "svc-noroles", "svc2-secret")
    st, body = http("GET", f"{base}/admin/realms/{realm}/users", token=svc2)
    print(f"    GET /admin/realms/{realm}/users -> {st} {str(body)[:80]}")


if __name__ == "__main__":
    sys.exit(main())