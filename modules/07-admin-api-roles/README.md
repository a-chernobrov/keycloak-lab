# Модуль 07 — Admin REST API, service accounts и избыточные роли

**Цель:** показать, как избыточные привилегии service-account клиента превращаются
в полный доступ к admin REST API (эскалация), и как отличить это от корректной настройки.

---

## 1. Теория

### 1.1 Admin REST API

`/admin/realms/<realm>/...` — управление realm'ом (пользователи, клиенты, роли).
Требует access-токен с нужными ролями клиента `realm-management`
(`view-users`, `manage-users`, `realm-admin` и т.д.).

### 1.2 Service accounts

Клиент с `serviceAccountsEnabled: true` получает «сервис-аккаунт» (обычный пользователь
`service-account-<client>`), которому можно выдать роли. Токен берётся через
`grant_type=client_credentials`.

### 1.3 Принцип наименьших привилегий

Опасности:
- выдача **`realm-admin`** (полные права), когда достаточно `view-users`;
- роль `realm-management` вместо узких ролей конкретного клиента;
- **`Full Scope Allowed`** у клиента — клиент автоматически получает все роли пользователя;
- лишние роли в токене (protocol mappers) расширяют доступ у RS.

Сервис-аккаунты часто забывают и не ротируют их секреты — это «долгоживущий» доступ.

---

## 2. Что настроено в лабе

- realm `vulnerable`. Скрипт `admin_api_demo.py` создаёт два service-account клиента:
  - `svc-overprivileged` — с ролью `realm-admin` (антипример);
  - `svc-noroles` — без ролей (корректная настройка).

---

## 3. Практика (проверенные результаты)

```bash
python3 scripts/admin_api_demo.py
```

```
=== 1) admin API без токена ===
    GET /admin/realms/vulnerable/users -> 401

=== 2) service account с избыточной ролью realm-admin ===
    создан клиент svc-overprivileged, роль realm-admin выдана сервис-аккаунту

=== 3) client_credentials-токен -> admin API ===
    GET /admin/realms/vulnerable/users -> 200 (users=3)

=== 4) сравнение: service account БЕЗ ролей ===
    GET /admin/realms/vulnerable/users -> 403
```

### Проверенная таблица

| Проверка | Результат | Вывод |
|---|---|---|
| admin API без токена | `401` | доступ защищён |
| service account с `realm-admin` | `200` (список юзеров) | избыточная роль = полный admin |
| service account без ролей | `403` | минимум привилегий работает |
| вывод токена клиента | `grant_type=client_credentials` | не требует пользователя |

### Ручной эквивалент

```bash
BASE=http://keycloak.127.0.0.1.nip.io:8080
TOKEN=$(curl -s -d grant_type=client_credentials -d client_id=svc-overprivileged -d client_secret=svc-secret \
  $BASE/realms/vulnerable/protocol/openid-connect/token | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -H "Authorization: Bearer $TOKEN" $BASE/admin/realms/vulnerable/users | head -c 300
```

---

## 4. Упражнения

| # | Что сделать | На что смотреть |
|---|---|---|
| 1 | Выдать `svc-noroles` только `view-users` | какой минимум нужен для листинга |
| 2 | Сравнить `realm-admin` vs `manage-users` vs `view-users` | гранулярность ролей |
| 3 | Включить у клиента `Full Scope Allowed` | какие роли попадут в токен |
| 4 | Посмотреть claims сервис-токена (`/api/me` из модуля 05) | что видит RS |
| 5 | Найти в realm'е клиентов с `serviceAccountsEnabled` | потенциальные «вечные» доступы |

---

## 5. Ремедиация

- Принцип наименьших привилегий: узкие роли (`view-users`) вместо `realm-admin`.
- Ограничивать `Full Scope Allowed`; явно назначать client scope/роли.
- Ротировать секреты service-account клиентов; отключать неиспользуемые.
- Аудит (`admin events`) включён; алерты на выдачу `realm-admin`/создание клиентов.
- Сетевой доступ к admin API ограничен; не публиковать `/admin` наружу.