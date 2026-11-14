# Модуль 06 — Self-registration: enumeration, отсутствие верификации email

**Цель:** показать риски открытой саморегистрации: user enumeration, регистрация на чужой
email без верификации, отсутствие rate-limit, а также DCR (dynamic client registration).

---

## 1. Теория

### 1.1 Что такое self-registration

При `registrationAllowed: true` доступна форма регистрации
(`/realms/<r>/login-actions/registration?...`). Если она не нужна бизнесу — это лишняя
поверхность атаки.

### 1.2 User enumeration

Форма регистрации — оракул: занятый `username`/`email` даёт ошибку
(«Username already exists»), свободный — продолжает флоу. Так перечисляются
существующие учётки (аналогично — forgot-password при определённых настройках).

### 1.3 Email verification

Если `verifyEmail: false`, пользователь создаётся и входит **без подтверждения email**.
Атакующий регистрируется на чужой адрес, а жертва потом может получить письма/сброс
пароля на этот адрес → захват.

### 1.4 Rate-limit

Отсутствие ограничений на регистрацию/сброс пароля → массовая энумерация, спам,
занятие имён (username squatting).

### 1.5 DCR

`registration_endpoint` (`/realms/<r>/clients-registrations/openid-connect`) позволяет
регистрировать OAuth-клиенты. Если он открыт (без Initial Access Token), атакующий
заводит свои клиенты с нужными redirect_uri.

---

## 2. Что настроено в лабе

realm `vulnerable`:
- `registrationAllowed: true`, `verifyEmail: false`, `registrationEmailAsUsername: false`;
- `duplicateEmailsAllowed: false` (поэтому email тоже энумерируется);
- rate-limit отсутствует.

---

## 3. Практика (проверенные результаты)

### 3.1 Регистрация на чужой email

```bash
python3 scripts/register_user.py --username eve --email victim@lab.local
```

```
[*] register username=eve email=victim@lab.local
    status=302 location=http://app.127.0.0.1.nip.io:8088/callback?...&code=0e22bfde-...
    => зарегистрирован (redirect)
```

### 3.2 Вход сразу после регистрации (email не верифицирован)

```bash
curl -s -d 'grant_type=password&client_id=sp-app&client_secret=sp-app-secret&username=eve&password=Passw0rd!' \
  http://keycloak.127.0.0.1.nip.io:8080/realms/vulnerable/protocol/openid-connect/token \
  | python3 -c 'import sys,json;print("OK" if "access_token" in json.load(sys.stdin) else "ERR")'
# OK — токен получен без верификации email
```

### 3.3 User enumeration через форму регистрации

```bash
python3 scripts/register_user.py --username alice --email newmail@lab.local
```

```
[*] register username=alice email=newmail@lab.local
    status=200 location=-
    hint: Username already exists.
    => username/email уже существует (enumeration oracle)
```

### 3.4 DCR без токена

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Content-Type: application/json' \
  -d '{"clientId":"evil"}' \
  http://keycloak.127.0.0.1.nip.io:8080/realms/vulnerable/clients-registrations/openid-connect
# 400 — регистрация клиента без Initial Access Token отклонена (защита включена)
```

### Проверенная таблица

| Проверка | Результат | Вывод |
|---|---|---|
| Регистрация на `victim@lab.local` | 302 + code | email не защищён |
| Вход за нового пользователя | OK | `verifyEmail: false` |
| Регистрация существующего `alice` | `Username already exists.` | enumeration |
| DCR `POST clients-registrations` | `400` | требует Initial Access Token |

---

## 4. Упражнения

| # | Что сделать | На что смотреть |
|---|---|---|
| 1 | Перебрать username'ы по словарю через форму | как быстро строится список юзеров |
| 2 | Включить `verifyEmail` и повторить | что меняется в флоу |
| 3 | Включить brute-force detection и проверить | влияние на enum/перебор |
| 4 | Сравнить с realm `production` (`registrationAllowed: false`) | почему закрытая регистрация безопаснее |
| 5 | Проверить forgot-password на enumeration | одинаковые ли ответы для существующего/нет |

---

## 5. Ремедиация

- Отключать self-registration, если он не нужен (`registrationAllowed: false`).
- Включать `verifyEmail` и `registrationEmailAsUsername` где уместно.
- Единообразные ответы форм (без «уже существует»), либо защита капчей/rate-limit.
- Ограничение частоты на регистрацию/сброс пароля (brute-force detection).
- DCR — только с Initial Access Token и строгими политиками (allowed redirect_uri, scopes).