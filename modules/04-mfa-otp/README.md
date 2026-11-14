# Модуль 04 — MFA / OTP: обход 2FA при общем TOTP-секрете

**Цель:** понять, почему «2FA настроена», но не защищает, и научиться использовать
свою учётную запись (или известный секрет) для входа в чужую.

Стенд: Keycloak 26.x, realm `vulnerable`, клиент `direct-grant` (ROPC).

---

## 1. Теория

### 1.1 Как устроен TOTP

TOTP (RFC 6238) — это HOTP с временным счётчиком вместо инкремента:

```
counter = floor(unixtime / period)          # period обычно 30s
code    = HOTP(secret, counter)             # HMAC-SHA1, dynamic truncation, 6 цифр
```

Сервер и «аутентификатор» делят один секрет. Знает секрет — генерируешь валидные коды.
Проверка допускает окно `lookAheadWindow` (обычно ±1 период) на дрейф часов.

### 1.2 Ключевая деталь Keycloak: секрет используется как есть

Keycloak валидирует OTP так (см. `validateTOTP(token, secret.getBytes())`):

```
ключ HMAC = СЫРЫЕ БАЙТЫ строки секрета   (secret.getBytes())
```

Не base32-декод (как делает Google Authenticator по `otpauth://`), а именно строка.
Поэтому генератор [totp.py](../../scripts/totp.py) по умолчанию использует
`key_encoding="raw"`. Если взять base32-декод — **ни один код не подойдёт**.
Проверено на стенде (см. §3.3).

### 1.3 Где ломается 2FA

«Всплывший TOTP, одинаковый для всех» — это не один баг, а семейство первопричин:

| Вектор | Первопричина | В этом модуле |
|---|---|---|
| **Общий/дефолтный TOTP-секрет** | всем юзерам выдан один секрет (импорт, кастомный provisioning, утечка QR) | **да (4.a)** |
| OTP не подключён к Direct Grant | в browser flow OTP есть, в Direct Grant — нет | вариация |
| OTP не обязателен | `Configure OTP` не в required actions | — |
| Клиент с «дырявым» flow | у клиента свой flow без OTP-экзекуции | — |
| Слабый OTP-policy | большой `otpPolicyLookAheadWindow`, нет rate-limit и reuse-prevention | — |
| Реплей/откат шага | нет защиты от повторного использования кода | — |
| Утечка секрета через кастомный эндпоинт | SPI/микросервис отдаёт `totp_secret` | (план: модуль 07) |

**Сценарий 4.a (реализован):** в организации всем сотрудникам выдали **один и тот же**
TOTP-секрет. Атакующий получает пароль жертвы (фишинг/утечка/credential stuffing) —
и, зная общий секрет, генерирует валидный код. Второй фактор не останавливает вход.

---

## 2. Что настроено в лабе

- realm `vulnerable`, клиенты `direct-grant` (ROPC) и `sp-app`;
- Direct Grant flow содержит `Direct Grant - Conditional OTP`: если у юзера настроен OTP —
  он **обязателен**;
- юзеры `alice` (жертва) и `mallory` (атакующий) имеют **общий** TOTP-секрет
  `JBSWY3DPEHPK3PXP`, заданный в [vulnerable-realm.json](../../realms/vulnerable-realm.json);
- скрипты для переключения «общий ↔ уникальный» секрет.

> В Keycloak 26 эндпоинт `POST .../users/{id}/credentials` не поддерживается (404),
> поэтому OTP-секрет задаётся через `partialImport` (см. `seed_totp.py`). При этом
> у пользователя обязаны быть `firstName`/`lastName`, иначе login падает с
> `Account is not fully set up`.

> **Anti-replay:** Keycloak не принимает повторно один и тот же OTP-код в пределах окна.
> При повторных прогонах демо нужно выждать смену окна (~30s) или сменить пользователя.

---

## 3. Практика (проверенные результаты)

Все команды запускаются из каталога `lab/`.

### 3.1 Уязвимо: общий секрет (состояние по умолчанию)

```bash
python3 scripts/login_totp.py --username alice --password 'Passw0rd!' --secret JBSWY3DPEHPK3PXP
```

```
[*] TOTP-код из общего секрета: 003449 (осталось 28s)
[+] УСПЕХ: получен токен для 'alice' без второго фактора жертвы
    access_token: eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJPLVZzajdx...
    expires_in:   3600s
```

Ключевое: атакующему **не нужен** телефон/аутентификатор жертвы — достаточно знания
общего секрета. Тот же код проходит и для `mallory` (проверено).

### 3.2 Исправлено: уникальный секрет на пользователя

```bash
python3 scripts/seed_totp.py --users alice mallory --unique
# alice   -> OTP secret = IWSRELLE5DXQESSQ
# mallory -> OTP secret = N63IIVLSU3MNOIKR

# alice входит своим секретом — успех
python3 scripts/login_totp.py --username alice --password 'Passw0rd!' --secret IWSRELLE5DXQESSQ

# mallory пытается войти в alice СВОИМ секретом — провал
python3 scripts/login_totp.py --username alice --password 'Passw0rd!' --secret N63IIVLSU3MNOIKR
```

```
[!] Отказ (401) — OTP не принят: {"error":"invalid_grant","error_description":"Invalid user credentials"}
```

Вернуть уязвимое состояние обратно:

```bash
python3 scripts/seed_totp.py --users alice mallory --shared JBSWY3DPEHPK3PXP
```

### 3.3 Проверенные результаты

| Проверка | Команда | Результат | Вывод |
|---|---|---|---|
| Вход с общим секретом | `login_totp.py --username alice --secret JBSW...` | `200` + токен | 2FA обойдена |
| Тот же код для второй учётки | `--username mallory --secret JBSW...` | `200` + токен | секрет общий на всех |
| Уникальные секреты, свой | `--secret IWSR...` (alice) | `200` + токен | легитимный вход |
| Уникальные секреты, чужой | `--secret N63I...` для alice | `401 invalid_grant` | исправление работает |
| Пароль без OTP (OTP настроен) | ROPC без `totp` | `401 invalid_grant` | OTP реально требуется |
| Генератор с base32-декодом | `totp.py JBSWY3DPEHPK3PXP --base32` | `401` | **Keycloak ждёт raw-байты секрета** |

---

## 4. Упражнения

| # | Что сделать | На что смотреть |
|---|---|---|
| 1 | Сгенерировать код и войти за `alice` с общим секретом | подтвердить обход без второго фактора жертвы |
| 2 | Перегенерировать коды во времени, зайти при `lookAheadWindow=1` | почему окно расширяет поверхность атаки |
| 3 | Переключить на `--unique` и повторить | убедиться, что чужой секрет не подходит |
| 4 | Сравнить код при `--base32` и без | понять, как именно Keycloak трактует секрет |
| 5 | Войти через браузер (`sp-app` → `/login`) | убедиться, что OTP требуется и в интерактиве |

---

## 5. Ремедиация

- **Уникальный секрет на пользователя** (главное) — никакого shared/дефолтного секрета.
- Запретить импорт OTP-секретов из внешних источников без ротации.
- Ограничить `otpPolicyLookAheadWindow` (1), включить rate-limit и reuse-prevention для OTP.
- Требовать OTP в Direct Grant flow (или отключить ROPC вовсе).
- Мониторинг: один и тот же OTP-код, принятый для разных `sub`, — сигнал.
- Не отдавать `totp_secret`/секреты через кастомные SPI/микросервисы.