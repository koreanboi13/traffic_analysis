# Руководство по настройке и запуску дистрибутива ПО

> Полный алгоритм установки и запуска дистрибутива(вов) ПО системы (т.н. "release") в среде исполнения. ОС 

## Переменные окружения

> Таблица с описанием назначения переменных окружения, допустимыми значениями и значением по-умолчанию.

### WAF сервис

| Имя переменной | Описание | Допустимые значения | Значение по-умолчанию |
| -------------- | -------------------------------- | ------------------- | --------------------- |
| WAF_CONFIG_PATH | Путь к файлу конфигурации WAF | Путь к YAML-файлу | `config.yaml` |
| WAF_POSTGRES_HOST | Хост PostgreSQL для WAF | hostname / IP | `localhost` |
| WAF_POSTGRES_PORT | Порт PostgreSQL для WAF | 1024-65535 | `5432` |
| WAF_POSTGRES_USER | Пользователь PostgreSQL | строка | `waf` |
| WAF_POSTGRES_PASSWORD | Пароль PostgreSQL | строка | `waf_secret` |
| WAF_POSTGRES_DB | Имя базы данных PostgreSQL | строка | `waf` |
| WAF_POSTGRES_SSL_MODE | Режим SSL для PostgreSQL | disable, require, verify-ca, verify-full | `disable` |

### Teststand

| Имя переменной | Описание | Допустимые значения | Значение по-умолчанию |
| -------------- | -------------------------------- | ------------------- | --------------------- |
| DATABASE_URL | Connection string для PostgreSQL teststand | PostgreSQL DSN | `postgres://teststand:teststand@teststand-db:5432/teststand?sslmode=disable` |
| PORT | Порт HTTP-сервера teststand | 1024-65535 | `8888` |

### Teststand PostgreSQL (prod)

| Имя переменной | Описание | Допустимые значения | Значение по-умолчанию |
| -------------- | -------------------------------- | ------------------- | --------------------- |
| TEST_POSTGRES_DB | Имя базы данных teststand | строка | `teststand` |
| TEST_POSTGRES_USER | Пользователь PostgreSQL teststand | строка | `teststand` |
| TEST_POSTGRES_PASSWORD | Пароль PostgreSQL teststand | строка | `teststand` |

## Конфигурация WAF (config.yaml)

Основной файл конфигурации WAF — `waf/config.yaml`. Структура:

| Секция | Параметр | Описание | Значение по-умолчанию |
|--------|----------|----------|----------------------|
| `proxy` | `listen_addr` | Адрес прослушивания прокси | `:8080` |
| `proxy` | `backend_url` | URL защищаемого приложения | `http://teststand-app:8888` |
| `analysis` | `max_body_size` | Максимальный размер тела для анализа (байт) | `1048576` (1 МБ) |
| `analysis` | `max_decode_passes` | Максимальное число проходов декодирования | `3` |
| `clickhouse` | `addr` | Адрес ClickHouse (native protocol) | `clickhouse:9000` |
| `clickhouse` | `database` | Имя базы данных ClickHouse | `waf` |
| `clickhouse` | `batch_size` | Размер батча для записи событий | `100` |
| `clickhouse` | `flush_interval` | Интервал принудительного flush | `1s` |
| `logging` | `level` | Уровень логирования | `info` |
| `logging` | `format` | Формат логов | `json` |
| `detection` | `rules_file` | Путь к файлу правил | `rules.yaml` |
| `detection` | `log_threshold` | Порог score для логирования | `3` |
| `detection` | `block_threshold` | Порог score для блокировки | `7` |
| `detection` | `enabled` | Включить/выключить детекцию | `true` |
| `auth` | `jwt_secret` | Секрет для подписи JWT-токенов | `dev-secret-change-me` |
| `auth` | `token_ttl` | Время жизни JWT-токена | `24h` |
| `admin_api` | `listen_addr` | Адрес прослушивания Admin API | `:8090` |
| `metrics` | `listen_addr` | Адрес прослушивания метрик | `:9090` |

## Требования к среде

- Docker Engine 20.x+ (рекомендуется 24.x+)
- docker-compose v2
- Свободные порты: 8081 (proxy), 8090 (admin API), 9090 (metrics), 8123 (ClickHouse HTTP), 5173 (panel dev)

## Алгоритм запуска (Development)

1. Клонировать репозиторий:
   ```bash
   git clone <repository-url>
   cd traffic_analysis
   ```

2. Запустить все сервисы:
   ```bash
   docker-compose up --build
   ```

3. Дождаться прохождения health check всех сервисов (teststand-db, clickhouse, waf-postgres).

4. Запустить панель в режиме разработки:
   ```bash
   cd panel
   npm install
   npm run dev
   ```

5. Доступные URL:
   - Панель: `http://localhost:5173`
   - WAF Proxy: `http://localhost:8081`
   - Admin API: `http://localhost:8090`
   - Metrics: `http://localhost:9090/metrics`
   - ClickHouse HTTP: `http://localhost:8123`

## Алгоритм запуска (Production)

1. Создать файл `.env` с переменными окружения:
   ```env
   WAF_CONFIG_PATH=/app/config.yaml
   WAF_POSTGRES_HOST=waf-postgres
   WAF_POSTGRES_PORT=5432
   WAF_POSTGRES_USER=waf
   WAF_POSTGRES_PASSWORD=<secure-password>
   WAF_POSTGRES_DB=waf
   WAF_POSTGRES_SSL_MODE=disable
   TEST_POSTGRES_DB=teststand
   TEST_POSTGRES_USER=teststand
   TEST_POSTGRES_PASSWORD=<secure-password>
   ```

2. Запустить с prod-оверрайдами:
   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
   ```

3. Prod-конфигурация добавляет:
   - Persistent volumes для данных PostgreSQL и ClickHouse.
   - Политику `restart: unless-stopped` для всех сервисов.
   - ClickHouse доступен только через внутреннюю сеть Docker (не через `ports`, а через `expose`).

## Остановка сервисов

```bash
# Development
docker-compose down

# Production (с сохранением данных)
docker-compose -f docker-compose.yml -f docker-compose.prod.yml down

# Production (с удалением данных)
docker-compose -f docker-compose.yml -f docker-compose.prod.yml down -v
```
