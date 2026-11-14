# Модуль 02 — Realm и Client enumeration

**Цель:** составить карту тенанта — какие realm'ы живут, какие клиенты в них
зарегистрированы и какого они типа. Это фундамент для всех последующих атак.

---

## 1. Теория

### 1.1 Realm enumeration

Realm — изолированный тенант. Проверка существования тривиальна:

```
GET /realms/<name>/.well-known/openid-configuration
200 -> realm существует, 404 -> нет
```

По словарю частых имён (`master`, `internal`, `staging`, `dev`, `<company>`) можно найти
«забытые» realm'ы, у которых обычно слабее настройки.

### 1.2 Client enumeration (error-based oracle)

Authorization endpoint по-разному отвечает на `client_id`:

| Ответ | Значит |
|---|---|
| `Client not found` | клиента нет |
| `Invalid parameter: redirect_uri` | клиент **есть**, но redirect_uri не разрешён |
| страница логина | клиент есть, redirect_uri ок |

Так можно перебирать `client_id` по словарю, не имея доступа к admin API.
Плюс всегда присутствуют встроенные клиенты: `account`, `account-console`, `admin-cli`,
`security-admin-console`.

### 1.3 Что это даёт

- Список клиентов → выбор «дырявого» (public без PKCE, implicit, широкий redirect_uri).
- Существование realm → база для брутфорса/регистрации.

---

## 2. Что настроено в лабе

- realm `vulnerable` с клиентами `sp-app`, `direct-grant`, `public-spa` (+ встроенные);
- realm `production` со своим `sp-app`.

---

## 3. Практика (проверенные результаты)

```bash
python3 scripts/enum_clients.py
```

```
[*] realm enumeration
    [EXISTS] master       200
    [EXISTS] vulnerable   200
    [EXISTS] production   200
    [      ] internal     404
    [      ] staging      404
    [      ] dev          404
    [      ] test         404
    [      ] admin        404

[*] client enumeration in realm 'vulnerable'
    [EXISTS] sp-app                 exists (login/redirect)
    [EXISTS] direct-grant           exists (redirect_uri rejected)
    [EXISTS] public-spa             exists (login/redirect)
    [EXISTS] account                exists (redirect_uri rejected)
    [EXISTS] account-console        exists (redirect_uri rejected)
    [EXISTS] admin-cli              exists (redirect_uri rejected)
    [  ?   ] broker                 unclear (403)
    [EXISTS] security-admin-console exists (redirect_uri rejected)
    [  ?   ] realm-management       unclear (403)
```

### Проверенная таблица

| Проверка | Результат | Вывод |
|---|---|---|
| realm `vulnerable` | `200` | существует |
| realm `staging` | `404` | нет |
| client `sp-app` | login/redirect | существует, redirect_uri допустим |
| client `direct-grant` | redirect_uri rejected | существует, но redirect_uri не разрешён |
| client `nosuch` | `Client not found` | oracle работает |

### Ручные варианты

```bash
BASE=http://keycloak.127.0.0.1.nip.io:8080
# существующий клиент
curl -s "$BASE/realms/vulnerable/protocol/openid-connect/auth?client_id=sp-app&response_type=code&redirect_uri=http://app.127.0.0.1.nip.io:8088/callback&scope=openid" | grep -o '<title>[^<]*'
# несуществующий
curl -s "$BASE/realms/vulnerable/protocol/openid-connect/auth?client_id=nosuch&response_type=code&scope=openid" | grep -io 'client not found'
```

---

## 4. Упражнения

| # | Что сделать | На что смотреть |
|---|---|---|
| 1 | Расширить словарь realm'ов | по каким именам стоит брутить в реальности |
| 2 | Определить тип клиента (public/confidential) | у public нет секрета, включён PKCE? |
| 3 | Найти клиент с implicit flow | вектор утечки токена (модуль 03) |
| 4 | Сравнить набор клиентов `vulnerable` и `production` | что выдали лишнего |

---

## 5. Ремедиация

- Не держать лишних realm'ов/клиентов; удалять test/staging из прод-контура.
- Отключить ненужные flows у клиентов (implicit, direct grant).
- Не раскрывать лишнего в ответах authorization endpoint (единообразные ошибки).
- Ограничить redirect_uri точными значениями (см. модуль 03).