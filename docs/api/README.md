# Описание внешних функций API 
> **Требования к описанию API**
> 1. Нотация OpenAPI v3.
> 2. Должны быть указаны все входные и выходные параметры.
> 3. Должны быть помечены обязательные входные параметры, возможные значения и примеры заполнения.
> 4. Расположение: `docs/api/swagger.yaml` или `swagger.json`.
> 5. Каждый метод должен сопровождаться всеми возможными ошибками на данный метод.

Полная спецификация API в формате OpenAPI v3 находится в файле [`swagger.yaml`](swagger.yaml).

# Требования к структурам ошибок
> Возвращаемые ошибки должны быть интегрированы в описание API (OpenAPI).
> Каждая ошибка должна частично соответствовать стандарту «Problem Details» (RFC 7807/9457):
> 1. `title` - краткое описание ошибки.
> 2. `detail` - подробное описание ошибки и способа ее устранения.
> 3. `requestId` - уникальный идентификатор запроса в формате UUIDv7 (время-зависимый), по которому можно найти запрос в журнале событий ("логах").
> 4. `timestamp` - метка времени в формате UTC.
> 
> Обязательные поддерживаемые коды:
> - **2xx: Success (успешно):**
>     - 200 OK («хорошо»);
>     - 201 Created («создано»);
>     - 202 Accepted («принято»);
> - **4xx: Client Error (ошибка клиента):**
>     - 400 Bad Request («неправильный, некорректный запрос»);
>     - 401 Unauthorized («не авторизован»);
>     - 403 Forbidden («запрещено (не уполномочен)»);
>     - 404 Not Found («не найдено»);
>     - 405 Method Not Allowed («метод не поддерживается»);
>     - 413 Payload Too Large («полезная нагрузка слишком велика»);
>     - 414 URI Too Long («URI слишком длинный»);
>     - 415 Unsupported Media Type («неподдерживаемый тип данных»);
>     - 418 I'm a teapot («я — чайник»);
>     - 429 Too Many Requests («слишком много запросов»).
> - **5xx: Server Error (ошибка сервера):**
>     - 500 Internal Server Error («внутренняя ошибка сервера»);
>     - 501 Not Implemented («не реализовано»);
>     - 502 Bad Gateway («плохой, ошибочный шлюз»);
>     - 503 Service Unavailable («сервис недоступен»);
>     - 504 Gateway Timeout («шлюз не отвечает»).

В сообществе существует рекомендуемый стандарт для структуры ошибок – **RFC 7807 "Problem Details for HTTP APIs"**, обновленный в 2023 году как RFC 9457. Он предлагает единый формат JSON для сообщений об ошибках (MIME-тип `application/problem+json`). 
## Тело ответа
В ответ на запрос с ошибкой HTTP 4XX/5XX необходимо добавлять JSON-тело ответа. 

Текущая реализация использует упрощённый формат ошибок:
  
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json
{
  "error": "invalid request body"
}
```

Для соответствия RFC 7807/9457 рекомендуется расширить формат:

```http
HTTP/2.0 403 Forbidden  
Content-Type: application/problem+json  
{  
  "requestId": "019000a1-b2c3-7d4e-5f6a-7b8c9d0e1f2a",  
  "title": "You do not have enough permissions.",  
  "detail": "Роль 'analyst' не имеет прав на модификацию правил. Обратитесь к администратору.",  
  "timestamp": "2026-04-09T12:30:00Z"  
}
```

# Описание API

## Аутентификация

### POST /api/auth/login

Аутентификация пользователя и получение JWT-токена.

**Тело запроса:**
```json
{
  "username": "admin",
  "password": "password123"
}
```

**Ответы:**
- `200 OK` — успешная аутентификация
  ```json
  {
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_at": 1712764800
  }
  ```
- `400 Bad Request` — невалидное тело запроса
- `401 Unauthorized` — неверный логин или пароль
- `500 Internal Server Error` — внутренняя ошибка

## Health Check

### GET /api/health

Проверка доступности Admin API.

**Ответы:**
- `200 OK`
  ```json
  {"status": "ok"}
  ```

## Правила

### GET /api/rules

Получение списка всех правил. Требует JWT-токен.

**Ответы:**
- `200 OK` — массив правил
  ```json
  [
    {
      "ID": "sqli-sig-001",
      "Name": "SQLi UNION SELECT",
      "Type": "regex",
      "Category": "sqli",
      "Pattern": "(?i)(?:union)\\s+(?:all\\s+)?(?:select)",
      "Heuristic": "",
      "Threshold": 0,
      "Targets": ["query", "body"],
      "Weight": 9,
      "Enabled": true,
      "LogOnly": false
    }
  ]
  ```
- `401 Unauthorized` — невалидный токен
- `500 Internal Server Error` — ошибка сервера

### GET /api/rules/{id}

Получение правила по идентификатору. Требует JWT-токен.

**Параметры пути:**
- `id` (string, обязательный) — идентификатор правила

**Ответы:**
- `200 OK` — объект правила
- `401 Unauthorized` — невалидный токен
- `404 Not Found` — правило не найдено
- `500 Internal Server Error` — ошибка сервера

### POST /api/rules

Создание нового правила. Требует JWT-токен с ролью Admin.

**Тело запроса:**
```json
{
  "rule_id": "custom-001",
  "name": "Custom SQLi pattern",
  "type": "regex",
  "category": "sqli",
  "pattern": "(?i)exec\\s*\\(",
  "targets": ["query", "body"],
  "weight": 6,
  "enabled": true,
  "log_only": false
}
```

**Обязательные поля:** `rule_id`, `name`, `type`, `category`, `weight` (> 0).

**Ответы:**
- `201 Created` — правило создано
- `400 Bad Request` — невалидное тело или отсутствуют обязательные поля
- `401 Unauthorized` — невалидный токен
- `403 Forbidden` — недостаточно прав (роль не Admin)
- `500 Internal Server Error` — ошибка сервера

### PUT /api/rules/{id}

Обновление существующего правила. Требует JWT-токен с ролью Admin.

**Параметры пути:**
- `id` (string, обязательный) — идентификатор правила

**Тело запроса:** аналогично POST, без поля `rule_id`.

**Обязательные поля:** `name`, `type`, `category`, `weight` (> 0).

**Ответы:**
- `200 OK` — правило обновлено
- `400 Bad Request` — невалидное тело
- `401 Unauthorized` — невалидный токен
- `403 Forbidden` — недостаточно прав
- `404 Not Found` — правило не найдено
- `500 Internal Server Error` — ошибка сервера

### DELETE /api/rules/{id}

Удаление правила. Требует JWT-токен с ролью Admin.

**Параметры пути:**
- `id` (string, обязательный) — идентификатор правила

**Ответы:**
- `204 No Content` — правило удалено
- `401 Unauthorized` — невалидный токен
- `403 Forbidden` — недостаточно прав
- `500 Internal Server Error` — ошибка сервера

## События

### GET /api/events

Получение списка событий с фильтрацией. Требует JWT-токен.

**Query-параметры:**
| Параметр | Тип | Обязательный | Описание | Пример |
|----------|-----|-------------|----------|--------|
| `limit` | int | нет | Количество записей (макс. 100) | `20` |
| `offset` | int | нет | Смещение для пагинации | `0` |
| `ip` | string | нет | Фильтр по IP-адресу | `192.168.1.1` |
| `verdict` | string | нет | Фильтр по вердикту | `block` |
| `rule_id` | string | нет | Фильтр по ID правила | `sqli-sig-001` |
| `from` | string | нет | Начало периода (RFC3339) | `2026-01-01T00:00:00Z` |
| `to` | string | нет | Конец периода (RFC3339) | `2026-04-09T23:59:59Z` |

**Ответы:**
- `200 OK`
  ```json
  {
    "data": [...],
    "total": 1523,
    "offset": 0,
    "limit": 20
  }
  ```
- `401 Unauthorized` — невалидный токен
- `500 Internal Server Error` — ошибка сервера

### POST /api/events/export

Экспорт событий по фильтру. Требует JWT-токен.

**Тело запроса:**
```json
{
  "from": "2026-01-01T00:00:00Z",
  "to": "2026-04-09T23:59:59Z",
  "ip": "",
  "verdict": "block",
  "rule_id": "",
  "limit": 1000
}
```

**Ответы:**
- `200 OK` — массив событий (до 10000)
- `400 Bad Request` — невалидное тело запроса
- `401 Unauthorized` — невалидный токен
- `500 Internal Server Error` — ошибка сервера

## Proxy

### GET /healthz

Health check эндпоинт прокси-сервера.

**Ответы:**
- `200 OK` — прокси работает

### GET /metrics

Prometheus-метрики WAF.

**Ответы:**
- `200 OK` — метрики в формате Prometheus text exposition
