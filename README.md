# Keycloak Pentest Lab

Учебный стенд по пентесту Keycloak. Теория — в `../keycloak-pentest-methodology.md`,
практика — здесь. Единая версия: **Keycloak 26.x** (Quarkus). Приложение за ним —
намеренно примитивное (relying party), чтобы было куда логиниться.

```
[браузер] ──▶ sp-app (Flask OIDC-клиент) ──▶ Keycloak 26.x
                                              realm vulnerable — учебные уязвимости
                                              realm production — эталон настроек
```

## Требования

- Docker + Docker Compose
- Python 3 — для скриптов из `scripts/` (внешних зависимостей нет, только stdlib)

## Запуск

```bash
docker compose up -d --build
```

Первый запуск тянет образы и импортирует realm'ы (несколько десятков секунд).
Проверить готовность:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  http://keycloak.127.0.0.1.nip.io:8080/realms/vulnerable/.well-known/openid-configuration   # 200
```

| Адрес | Что это |
|---|---|
| <http://keycloak.127.0.0.1.nip.io:8080> | **Keycloak 26.x** — realm'ы `vulnerable` и `production` |
| <http://keycloak.127.0.0.1.nip.io:8080/admin> | admin-консоль (`admin` / `admin`) |
| <http://app.127.0.0.1.nip.io:8088> | **sp-app** — простое SP-приложение за Keycloak |
| <http://localhost:8090> | **vuln-rs** — уязвимый resource server (модуль 05) |
| <http://localhost:8091> | **rs-strict** — исправленный RS для сравнения (модуль 05) |

Управление:

```bash
docker compose stop            # остановить (контейнеры и данные Keycloak сохраняются)
docker compose up -d           # запустить снова
docker compose down            # удалить контейнеры -> данные Keycloak теряются, realm'ы пересоздадутся
docker compose down -v         # то же + удалить именованные volume'ы (в этой лабе их нет)
docker logs -f kc              # логи Keycloak
```

> Все скрипты запускать из каталога `lab/`.
> В лабе нет именованных volume'ов: H2 живёт в слое контейнера `kc`, поэтому любой `down`
> (даже без `-v`) сбрасывает данные, а `stop` — сохраняет.
> После сброса кастомные объекты (юзер `eve` из модуля 06, клиенты `svc-*` из модуля 07)
> исчезают — их создают соответствующие скрипты заново.

## Почему `*.127.0.0.1.nip.io`, а не `localhost`

Keycloak считает `localhost`/`127.0.0.1` «secure context» и ставит cookie
`AUTH_SESSION_ID; Secure; SameSite=None`. По http такая cookie не отправляется, и
**интерактивный логин (браузер, authorization code flow) ломается**.
`*.127.0.0.1.nip.io` резолвится в `127.0.0.1` (публичный wildcard-DNS, правка `/etc/hosts`
не нужна) — тогда Keycloak ставит обычную `SameSite=Lax` cookie и всё работает.

### Офлайн-режим (без публичного DNS)

Для работы без `nip.io` есть override-файл [docker-compose.offline.yml](docker-compose.offline.yml):

```bash
# 1) один раз прописать хосты (нужен sudo)
echo '127.0.0.1 keycloak.lab' | sudo tee -a /etc/hosts
echo '127.0.0.1 app.lab'      | sudo tee -a /etc/hosts

# 2) поднять стенд с override
docker compose -f docker-compose.yml -f docker-compose.offline.yml up -d --build

# 3) указать хосты скриптам
export KC_URL=http://keycloak.lab:8080
export SP_URL=http://app.lab:8088
```

Redirect URI обоих хостов уже разрешены в `realms/*.json`, поэтому конфиги руками править
не нужно. Скрипты берут базовые адреса из переменных окружения `KC_URL` / `SP_URL` / `RS_URL`
(иначе — значения по умолчанию с `nip.io`).

Прямой REST (ROPC/direct grant, энумерация) работает и через `localhost:8080` — cookie там не нужны.

## Учётные данные

| Что | Значение |
|---|---|
| admin | `admin` / `admin` |
| realm `vulnerable`: жертва | `alice` / `Passw0rd!` |
| realm `vulnerable`: атакующий | `mallory` / `Mall0ry!` |
| общий TOTP-секрет (vulnerable) | `JBSWY3DPEHPK3PXP` |
| realm `production`: пользователь | `bob` / `Bob_Str0ng!` |

> `production` — справочный эталон настроек (brute-force защита, короткие токены, PKCE).
> Приложения на его redirect-uri (`...:8089`) нет, а direct grant выключен — для практики
> используется realm `vulnerable`.

## Структура

```
docker-compose.yml
docker-compose.offline.yml      override для работы без публичного DNS (keycloak.lab/app.lab)
realms/
  vulnerable-realm.json        weak-настройки, юзеры alice/mallory, клиенты, общий OTP
  production-realm.json        эталон (brute-force защита, короткие токены, PKCE)
sp-app/                        простое Flask SP-приложение (login/callback/profile + /go)
vuln-rs/                       уязвимый resource server (модуль 05); rs-strict — исправленный
scripts/
  totp.py                      генератор TOTP; ключ = raw-байты (как в Keycloak)
  seed_totp.py                 OTP-секреты: --shared <s> (уязвимо) | --unique (исправлено)
  login_totp.py                ROPC с подстановкой TOTP
  login_flow.py                полный authorization code flow (пароль+OTP), возвращает redirect URL
  fingerprint.py               сборка/пути/заголовки/эндпоинты
  enum_realms.py               энумерация realm'ов
  enum_clients.py              энумерация realm'ов и клиентов (error-based)
  register_user.py             саморегистрация (enum, регистрация на чужой email)
  admin_api_demo.py            Admin API + service accounts / роли
  session_demo.py              refresh-ротация, logout, жизнь access-токена
  jwks.py / jwt_forge.py       PEM из JWKS + подделка JWT (alg=none, HS-confusion)
modules/<NN-тема>/README.md    теория + упражнения урока
```

## Модули

| # | Тема | Файл |
|---|---|---|
| 01 | Fingerprinting (сборка, пути, эндпоинты) | [01-fingerprint](modules/01-fingerprint/README.md) |
| 02 | Realm / Client enumeration | [02-realm-client-enum](modules/02-realm-client-enum/README.md) |
| 03 | Flows, redirect_uri / open redirect, утечка кода | [03-flows-redirect](modules/03-flows-redirect/README.md) |
| 04 | MFA / OTP: обход 2FA при общем секрете | [04-mfa-otp](modules/04-mfa-otp/README.md) |
| 05 | JWT: alg=none / HS256 confusion / aud | [05-jwt](modules/05-jwt/README.md) |
| 06 | Self-registration (enum, email verify) | [06-registration](modules/06-registration/README.md) |
| 07 | Admin API / роли / service accounts | [07-admin-api-roles](modules/07-admin-api-roles/README.md) |
| 08 | Сессии и logout | [08-sessions](modules/08-sessions/README.md) |

## Особенности Keycloak 26, важные для стенда

- **OTP-секрет трактуется как сырые байты строки** (`validateTOTP(token, secret.getBytes())`),
  а не base32-декод. Поэтому генератор использует `key_encoding="raw"`.
- **`POST /admin/.../users/{id}/credentials` не поддерживается** (404) — OTP-креденшел
  задаётся через `partialImport` (см. `seed_totp.py`).
- При `partialImport` с `OVERWRITE` у пользователя обязаны быть `firstName`/`lastName`,
  иначе login падает с `Account is not fully set up`.
- Keycloak **не принимает повторно один и тот же OTP-код** в пределах окна (anti-replay).