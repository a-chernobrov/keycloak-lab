# Модуль 05 — JWT: alg=none, RS256→HS256 confusion, aud/iss/exp

**Цель:** показать, что безопасность зависит не только от Keycloak, но и от того,
как **resource server (RS)** проверяет токен. Ошибки в проверке позволяют подделать
токен и выдать себя за другого пользователя.

Стенд: realm `vulnerable`, `vuln-rs` (`MODE=vuln`) и `rs-strict` (`MODE=strict`) — два RS
на одном и том же JWKS.

---

## 1. Теория

### 1.1 Где зона ответственности

Keycloak **подписывает** токены (RS256) и публикует публичный ключ в JWKS
(`/realms/<r>/protocol/openid-connect/certs`). Проверка подписи и claims — задача **RS**.
Поэтому `alg=none` и HS-confusion — это уязвимости RS/клиента, а не Keycloak.

### 1.2 `alg=none`

JWT позволяет `"alg":"none"` (без подписи). Если RS доверяет заголовку и не запрещает
`none` — токен принимается без всякой подписи.

### 1.3 RS256 → HS256 confusion

Публичный ключ RS256 — **публичный** (его отдаёт JWKS). Если RS при `alg=HS256` проверяет
HMAC-подпись, используя этот публичный ключ как секрет, атакующий подписывает свой токен
тем же публичным ключом (он известен) и проходит проверку.

### 1.4 Непроверяемые claims

Даже с валидной подписью RS обязан проверять `iss`, `aud`, `exp`, `nbf`. Если `aud` не
проверяется, токен, выпущенный для другого клиента/аудитории, принимается.

---

## 2. Что настроено в лабе

- `vuln-rs` (порт 8090, `MODE=vuln`):
  - принимает `alg=none`;
  - при `HS256` считает HMAC с ключом = **PEM публичного ключа** realm'а;
  - не проверяет `iss/aud/exp`;
  - `/api/admin` отдаёт «секрет», если в claims есть роль `admin`.
- `rs-strict` (порт 8091, `MODE=strict`): только RS256 + проверка `iss` — эталон.

---

## 3. Практика (проверенные результаты)

```bash
python3 scripts/jwt_forge.py --user admin --roles admin
```

```
[*] Realm public key (PEM):
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtSwm1wDJ95Swr7Wqv6Ce
... (публичный ключ realm'а из JWKS) ...
-----END PUBLIC KEY-----

[alg=none    ] token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJmb3JnZWQtc3ViIi...
    /api/me     -> 200 {"preferred_username":"admin", ...}
    /api/admin  -> 200 {"message":"SECRET ADMIN DATA","note":"accepted alg=none (NOT VERIFIED)","roles":["admin"]}

[HS256+pubkey] token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmb3JnZWQtc3ViIi...
    /api/me     -> 200 {"preferred_username":"admin", ...}
    /api/admin  -> 200 {"message":"SECRET ADMIN DATA","note":"accepted HS256 signed with PUBLIC key (confusion)","roles":["admin"]}
```

### Сравнение с исправленным RS

```bash
python3 scripts/jwt_forge.py --rs http://localhost:8091   # strict
```

| Токен | vuln-rs (8090) | rs-strict (8091) |
|---|---|---|
| `alg=none` | **200** + admin data | `401 alg none not allowed` |
| `HS256` + public key | **200** + admin data | `401 alg HS256 not allowed` |
| легитимный RS256 (from Keycloak) | 200 | 200 |

Легитимный RS256-токен можно получить и проверить так:

```bash
CODE=$(python3 scripts/totp.py JBSWY3DPEHPK3PXP)
TOKEN=$(curl -s -d "grant_type=password&client_id=direct-grant&client_secret=direct-grant-secret\
&username=alice&password=Passw0rd!&totp=$CODE" \
  http://keycloak.127.0.0.1.nip.io:8080/realms/vulnerable/protocol/openid-connect/token \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8091/api/me
```

### Проверенная таблица

| Проверка | Результат | Вывод |
|---|---|---|
| `alg=none` против vuln-rs | 200 | токен без подписи принимается |
| HS256 (ключ = публичный PEM) против vuln-rs | 200 | confusion работает |
| те же токены против strict | 401 | корректная проверка отклоняет |
| реальный RS256 против strict | 200 | strict не ломает легитимный вход |
| `/api/admin` по подделанному токену | 200 | эскалация до admin |

---

## 4. Упражнения

| # | Что сделать | На что смотреть |
|---|---|---|
| 1 | Убрать роль `admin` из claims | `/api/admin` → 403 |
| 2 | Поменять `iss` на чужой | почему strict отклоняет, vuln — нет |
| 3 | Получить свой реальный токен и сравнить claims с подделанным | какие claims RS вообще читает |
| 4 | Включить проверку `aud` в strict | чем помогает audience-контроль |
| 5 | Заменить `MODE` у vuln-rs на `strict` | как одна строка закрывает оба вектора |

---

## 5. Ремедиация

- Явно задавать разрешённые алгоритмы (только RS256/ES256); запрещать `none`.
- Никогда не использовать публичный ключ как HMAC-секрет; не смешивать симметричные и
  асимметричные алгоритмы.
- Ключи для проверки брать только из доверенного источника (JWKS по known URL).
- Проверять `iss`, `aud`, `exp`, `nbf`; сверять `aud` со своим `client_id`.
- Использовать проверенные библиотеки с явным списком `algorithms`.