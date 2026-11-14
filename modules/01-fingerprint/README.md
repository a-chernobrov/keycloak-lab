# Модуль 01 — Fingerprinting: сборка, пути, realm'ы

**Цель:** снять отпечаток инстанса Keycloak — определить сборку/префикс путей,
доступные эндпоинты, живые realm'ы и admin-консоль — ещё до атак.

---

## 1. Теория

### 1.1 Префикс путей = признак сборки

У Keycloak два типа сборок, и это видно по путям:
- **Quarkus** (современные) — всё под `/realms/...`;
- **WildFly** (старые) — всё под `/auth/realms/...`.

Различить их — один запрос. Это отсекает половину неактуальных техник/эндпоинтов.

### 1.2 Что раскрывает `openid-configuration`

`/realms/<realm>/.well-known/openid-configuration` (для master — доступен всегда) отдаёт
`issuer` и полный список эндпоинтов. По `issuer` видно базовый URL и префикс путей, а также
наличие `registration_endpoint` (DCR), `device_authorization_endpoint` и т.д.

### 1.3 Заголовки и ассеты консоли

- HTTP-заголовки (`Server`, `X-Powered-By`) на Quarkus часто пусты — это тоже признак.
- Admin-консоль `/admin/master/console/` отдаёт HTML со ссылкой на `/resources/<hash>/...`
  (хэш ассетов меняется между сборками).

---

## 2. Что настроено в лабе

- Keycloak 26.x (Quarkus), базовый URL `http://keycloak.127.0.0.1.nip.io:8080`;
- realm'ы `vulnerable` и `production` (плюс `master`);
- admin-консоль доступна по `/admin/`.

---

## 3. Практика (проверенные результаты)

```bash
python3 scripts/fingerprint.py
```

```
[*] Target: http://keycloak.127.0.0.1.nip.io:8080

[1] /realms/master/.well-known/openid-configuration -> 200
    issuer: http://keycloak.127.0.0.1.nip.io:8080/realms/master
    authorization_endpoint: .../realms/master/protocol/openid-connect/auth
    token_endpoint:         .../realms/master/protocol/openid-connect/token
    registration_endpoint:  .../realms/master/clients-registrations/openid-connect
    end_session_endpoint:   .../realms/master/protocol/openid-connect/logout
    device_authorization_endpoint: .../realms/master/protocol/openid-connect/auth/device
    => build: Quarkus (/realms)

[2] /auth/realms/master/.well-known/openid-configuration -> 404  (нет /auth-префикса => Quarkus)

[3] GET / -> 200
    Content-Type: text/html; charset=utf-8

[4] /admin/master/console/ -> 200
    asset: /resources/1fevr/admin/keycloak.v2/

[5] realm probe:
    master       200
    vulnerable   200
    production   200
    admin        404
    staging      404
    dev          404
```

### Проверенная таблица

| Проверка | Результат | Вывод |
|---|---|---|
| `issuer` без `/auth` | `.../realms/master` | сборка Quarkus |
| `/auth/realms/...` | `404` | старый префикс отсутствует |
| `registration_endpoint` в конфиге | присутствует | DCR включён → см. модуль 06 |
| заголовки корня | без `Server`/`X-Powered-By` | типично для Quarkus |
| admin-консоль | `200` | консоль снаружи доступна |

### Ручные варианты

```bash
BASE=http://keycloak.127.0.0.1.nip.io:8080
curl -s $BASE/realms/master/.well-known/openid-configuration | python3 -m json.tool | head
curl -s -o /dev/null -w '%{http_code}\n' $BASE/auth/realms/master/.well-known/openid-configuration  # 404 => Quarkus
curl -sI $BASE/ | head
```

---

## 4. Упражнения

| # | Что сделать | На что смотреть |
|---|---|---|
| 1 | Определить сборку по `issuer` и по `/auth` | почему `/auth` 404 = Quarkus |
| 2 | Найти в конфиге `registration_endpoint` | что он открывает (модуль 06) |
| 3 | Перечислить живые realm'ы | какие из них «забытые»/тестовые |
| 4 | Сравнить заголовки `vulnerable` и `production` | отличается ли что-то (в этой лабе — нет) |

---

## 5. Ремедиация / заметки

- Наличие `openid-configuration` — норма, но оно ускоряет атакующего: сразу видны эндпоинты
  и сборка.
- Не выставлять admin-консоль в интернет; ограничивать её по сети/IP.
- Держать актуальную версию (знать, какие CVE закрыты в текущей сборке).