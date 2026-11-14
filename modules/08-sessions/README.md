# Модуль 08 — Сессии, refresh-токены и logout

**Цель:** понять жизненный цикл сессии: ротация refresh-токена, что делает logout и почему
выданный access-токен продолжает работать после выхода.

---

## 1. Теория

### 1.1 Refresh token и ротация

Refresh-токен продлевает сессию. Ключевая настройка realm — **`revokeRefreshToken`**:
- **выкл** (по умолчанию) — старый refresh-токен остаётся валидным;
- **вкл** — при использовании refresh-токена выдаётся новый, старый инвалидируется.

Если ротации нет, украденный refresh-токен можно переиспользовать долго.

### 1.2 Logout

`/realms/<r>/protocol/openid-connect/logout` инвалидирует сессию (и refresh-токен).
`post_logout_redirect_uri` возвращает пользователя; back-channel logout уведомляет клиентов.

### 1.3 Access token stateless

Access-токен — JWT, подписанный Keycloak. RS проверяет подпись/claims локально и **не
обращается** к Keycloak. Поэтому после logout уже выданный access-токен **остаётся валидным**
до истечения `exp`. Отсюда важность короткого `accessTokenLifespan` и (опционально)
introspection/revocation-check на RS.

### 1.4 Back-channel logout

Если не настроен, клиенты не узнают о logout — «зависшие» сессии на стороне приложений.

---

## 2. Что настроено в лабе

realm `vulnerable`: `accessTokenLifespan: 3600`, `revokeRefreshToken` не задан (выкл);
`vuln-rs` (модуль 05) — RS без проверки revocation.

---

## 3. Практика (проверенные результаты)

```bash
python3 scripts/session_demo.py
```

```
[1] login OK (access_token, refresh_token)
[2] refresh #1 со старым RT -> 200
    refresh #2 тем ЖЕ (старым) RT -> 200: старый RT остаётся валиден -> revokeRefreshToken выключен [риск]
[3] logout -> 204
[4] refresh после logout -> 400 {'error': 'invalid_grant', 'error_description': 'Session not active'}
[5] RS http://localhost:8090/api/me старым access_token после logout -> 200  (ещё валиден)
```

### Проверенная таблица

| Проверка | Результат | Вывод |
|---|---|---|
| повторный refresh старым RT | `200` | RT **не ротируется** (`revokeRefreshToken` выкл) |
| logout | `204` | сессия завершена |
| refresh после logout | `400 Session not active` | refresh-токен инвалидирован |
| access token после logout на RS | `200` | JWT stateless — токен ещё «жив» |

> Из-за anti-replay OTP не запускайте демо `alice` сразу после другого логина `alice`
> в пределах 30s — смените пользователя (`--username mallory --password 'Mall0ry!'`)
> или выждите окно.

---

## 4. Упражнения

| # | Что сделать | На что смотреть |
|---|---|---|
| 1 | Включить `revokeRefreshToken` и повторить | старый RT перестанет работать |
| 2 | Уменьшить `accessTokenLifespan` | окно, в которое украденный AT полезен |
| 3 | Проверить `offline_access` scope | чем offline-сессия отличается |
| 4 | Настроить back-channel logout | как клиенты узнают о выходе |
| 5 | Настроить на RS проверку revocation/introspection | сколько «живёт» отозванный токен |

---

## 5. Ремедиация

- Включить **ротацию refresh-токена** (`revokeRefreshToken`) и reuse-detection.
- Короткий `accessTokenLifespan` + `refreshTokenMaxReuse` = 0.
- На RS — проверка `exp` (обязательно) и при необходимости introspection/revocation.
- Настроить back-channel/front-channel logout для клиентов.
- Ограничить/отключать `offline_access`, где он не нужен.