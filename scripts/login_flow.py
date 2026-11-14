#!/usr/bin/env python3
"""Полный authorization code flow через форму логина Keycloak (с паролем и OTP).

Возвращает ИТОГОВЫЙ redirect URL — то, что Keycloak отдаёт клиенту
(там видно `code`/`state`, либо `error`). Специально НЕ идём по редиректу
на сторону клиента (там может быть внешний домен), а фиксируем Location.

Пример:
  python3 login_flow.py --client-id public-spa \
      --redirect-uri "http://app.127.0.0.1.nip.io:8088/go?to=https://evil.example/steal"
"""
import argparse
import http.cookiejar
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

from totp import totp

HIDDEN_RE = re.compile(r'<input[^>]*type="hidden"[^>]*>', re.I)
INPUT_RE = re.compile(r'<input[^>]*>', re.I)
NAME_RE = re.compile(r'name="([^"]+)"')
VALUE_RE = re.compile(r'value="([^"]*)"')
ACTION_RE = re.compile(r'<form[^>]*action="([^"]+)"', re.I)

REDIRECT_CODES = (301, 302, 303, 307, 308)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Не следовать редиректам автоматически — обрабатываем сами."""
    def redirect_request(self, *args, **kwargs):
        return None


def _fetch(opener, url, data=None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    headers = {"User-Agent": "lab"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST" if data else "GET")
    try:
        return opener.open(req, timeout=15)
    except urllib.error.HTTPError as e:
        return e


def parse_form(html):
    """action формы + все именованные поля (не только hidden)."""
    m = ACTION_RE.search(html)
    action = m.group(1).replace("&amp;", "&") if m else None
    fields = {}
    for tag in INPUT_RE.findall(html):
        n = NAME_RE.search(tag)
        if n:
            v = VALUE_RE.search(tag)
            fields[n.group(1)] = v.group(1) if v else ""
    return action, fields


def auth_code_login(base, realm, client_id, redirect_uri, username, password,
                    totp_secret=None, response_type="code"):
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), _NoRedirect())
    kc_host = urllib.parse.urlparse(base).netloc

    q = {"client_id": client_id, "response_type": response_type,
         "scope": "openid profile email", "redirect_uri": redirect_uri, "state": "st"}
    resp = _fetch(opener, f"{base}/realms/{realm}/protocol/openid-connect/auth?{urllib.parse.urlencode(q)}")

    for _ in range(6):
        # редирект наружу (на клиента) — это и есть финал
        if resp.status in REDIRECT_CODES:
            loc = resp.headers.get("Location", "")
            if urllib.parse.urlparse(loc).netloc == kc_host:
                resp = _fetch(opener, loc)
                continue
            return loc

        html = resp.read().decode("utf-8", "ignore")
        action, fields = parse_form(html)
        if action is None:
            return resp.geturl()

        action = urllib.parse.urljoin(base, action)
        names = set(fields.keys())
        if "password" in names:
            fields["username"] = username
            fields["password"] = password
            resp = _fetch(opener, action, fields)
        elif "otp" in names:
            if not totp_secret:
                return resp.geturl()
            fields["otp"] = totp(totp_secret)
            resp = _fetch(opener, action, fields)
        else:
            return resp.geturl()

    return resp.geturl()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=os.environ.get("KC_URL", "http://keycloak.127.0.0.1.nip.io:8080"))
    p.add_argument("--realm", default="vulnerable")
    p.add_argument("--client-id", default="public-spa")
    p.add_argument("--redirect-uri",
                   default=os.environ.get("SP_URL", "http://app.127.0.0.1.nip.io:8088") + "/callback")
    p.add_argument("--username", default="alice")
    p.add_argument("--password", default="Passw0rd!")
    p.add_argument("--totp-secret", default="JBSWY3DPEHPK3PXP")
    p.add_argument("--response-type", default="code")
    a = p.parse_args()

    final = auth_code_login(a.url.rstrip("/"), a.realm, a.client_id, a.redirect_uri,
                            a.username, a.password, a.totp_secret, response_type=a.response_type)
    print(f"[*] final redirect URL:\n    {final}")
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(final).query)
    for k in ("code", "state", "error", "error_description"):
        if k in qs:
            print(f"    {k} = {qs[k][0]}")


if __name__ == "__main__":
    sys.exit(main())