## 1 Общее описание системы

### Назначение

Traffic Analysis WAF — собственный Web Application Firewall (WAF) в формате reverse-proxy на языке Go, предназначенный для перехвата HTTP(S)-трафика веб-приложений, нормализации запросов и анализа их на наличие SQL-инъекций и XSS-атак. Система обеспечивает автоматическую фильтрацию вредоносного трафика и предоставляет веб-панель управления для настройки правил детекции и просмотра инцидентов безопасности.

### Описание системы

> Требования: `docs -> Описание системы`

Система состоит из следующих компонентов:

1. **WAF Reverse-Proxy** — сервис на Go, работающий как обратный прокси-сервер с middleware-цепочкой обработки запросов: parse → normalize → detect → decision. Перехватывает весь HTTP-трафик к защищаемому приложению и применяет правила детекции (сигнатурные и эвристические) для выявления SQL-инъекций и XSS-атак.

2. **Admin API** — REST API на Go (chi router) для управления правилами, просмотра событий, аутентификации и экспорта данных. Поддерживает RBAC с ролями Admin и Analyst.

3. **Web Panel** — одностраничное приложение на React 19 + TypeScript, предоставляющее графический интерфейс для:
   - Дашборда с графиками блокировок и метриками
   - Управления правилами (создание, редактирование, удаление, режим LogOnly)
   - Просмотра и фильтрации событий безопасности
   - Экспорта событий

4. **ClickHouse** — колоночная СУБД для хранения и аналитики событий WAF.

5. **PostgreSQL** — реляционная СУБД для хранения правил и пользователей панели управления.

6. **Teststand** — тестовое веб-приложение на Go с PostgreSQL, выступающее в роли защищаемого backend-сервиса.


#### Среда исполнения

| Название | Версии |
| -------- | ------ |
| Go | 1.25.x |
| Node.js | 22.x (для сборки панели) |
| Docker + docker-compose | compose v2 |
| ОС | Linux / Windows / macOS |

#### Хранилища данных

| Название | Версии |
| -------- | ------ |
| ClickHouse | 25.x (latest stable) |
| PostgreSQL | 16-alpine |

#### Библиотеки программных зависимостей 

| Название | Версии |
| -------- | ------ |
| `github.com/go-chi/chi/v5` | v5.2.5 |
| `github.com/ClickHouse/clickhouse-go/v2` | v2.44.0 |
| `go.uber.org/zap` | v1.27.1 |
| `github.com/spf13/viper` | v1.21.0 |
| `github.com/golang-jwt/jwt/v5` | v5.3.1 |
| `github.com/jackc/pgx/v5` | v5.9.1 |
| `github.com/prometheus/client_golang` | v1.23.2 |
| `github.com/hashicorp/golang-lru/v2` | v2.0.7 |
| `github.com/rs/cors` | v1.11.1 |
| `github.com/google/uuid` | v1.6.0 |
| `golang.org/x/crypto` | v0.49.0 |
| React | 19.x |
| TypeScript | 6.x |
| Vite | 8.x |
| TanStack Query | v5.x |
| React Router | v7.x |
| Zustand | v5.x |
| Recharts | v3.x |
| shadcn/ui | 4.x |
| Tailwind CSS | v4.x |

## 2 Функциональное назначение

### Описание внешних функций (API)

> Требования: `docs/api/README.md`.

Система предоставляет REST API для управления WAF. Подробное описание API в нотации OpenAPI v3 находится в `docs/api/swagger.yaml`.

Основные группы эндпоинтов:

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| POST | `/api/auth/login` | Аутентификация пользователя, получение JWT-токена | Публичный |
| GET | `/api/health` | Health check Admin API | Публичный |
| GET | `/api/rules` | Получение списка всех правил | Authenticated |
| GET | `/api/rules/{id}` | Получение правила по ID | Authenticated |
| POST | `/api/rules` | Создание нового правила | Admin |
| PUT | `/api/rules/{id}` | Обновление существующего правила | Admin |
| DELETE | `/api/rules/{id}` | Удаление правила | Admin |
| GET | `/api/events` | Список событий с фильтрацией | Authenticated |
| POST | `/api/events/export` | Экспорт событий по фильтру | Authenticated |
| GET | `/healthz` | Health check прокси | Публичный |
| GET | `/metrics` | Prometheus-метрики | Публичный |

#### Описание ошибок 

> Требования: `docs/api/README.md`.

Все ошибки API возвращаются в формате JSON:

```json
{
  "error": "описание ошибки"
}
```

Поддерживаемые коды ответов:

| Код | Описание | Контекст использования |
|-----|----------|----------------------|
| 200 OK | Успешный запрос | Получение данных |
| 201 Created | Ресурс создан | Создание правила |
| 204 No Content | Успешное удаление | Удаление правила |
| 400 Bad Request | Некорректный запрос | Невалидный JSON, отсутствуют обязательные поля |
| 401 Unauthorized | Не авторизован | Отсутствует или невалидный JWT-токен |
| 403 Forbidden | Запрещено | Недостаточно прав (Analyst пытается изменить правила) |
| 404 Not Found | Не найдено | Правило с указанным ID не существует |
| 500 Internal Server Error | Внутренняя ошибка сервера | Ошибка БД, непредвиденная ошибка |

### Руководство пользователя

> Требования: `docs/USER_SPECS`.

Подробное руководство пользователя находится в `docs/3_USER_SPECS.md`.

## 3 Алгоритм настройки и запуска 

### Структура директорий программы

> Описание директорий

```
traffic_analysis/
├── waf/                          # WAF сервис (Go)
│   ├── cmd/waf/                  # Входная точка приложения (main.go)
│   ├── config/                   # Загрузка конфигурации (viper)
│   ├── config.yaml               # Основной файл конфигурации
│   ├── rules.yaml                # Файл правил детекции
│   ├── internal/
│   │   ├── adapter/              # Слой адаптеров (инфраструктура)
│   │   │   ├── clickhouse/       # Адаптер ClickHouse (хранение событий)
│   │   │   ├── postgres/         # Адаптер PostgreSQL (правила, пользователи)
│   │   │   └── rulesfile/        # Загрузка правил из YAML-файла
│   │   ├── app/                  # Слой приложения
│   │   │   ├── admin/            # Admin API (роутер, хэндлеры, middleware)
│   │   │   │   ├── handler/      # HTTP-обработчики (auth, rule, event)
│   │   │   │   └── middleware/   # JWT, RBAC middleware
│   │   │   ├── metrics/          # Prometheus-метрики
│   │   │   └── proxy/            # Reverse-proxy (handler, router)
│   │   │       ├── handler/      # Обработчики: parse, normalize, detect, record
│   │   │       └── wafcontext/   # Контекст запроса WAF
│   │   ├── domain/               # Доменные модели (Event, Rule, User)
│   │   ├── eventwriter/          # Батч-запись событий в ClickHouse
│   │   └── usecase/              # Бизнес-логика
│   │       ├── admin/            # Сервисы панели (auth, rules, events)
│   │       ├── detection/        # Движок детекции (engine, heuristics, allowlist)
│   │       └── pipeline/         # Pipeline обработки (parse, normalize)
│   └── Dockerfile
├── panel/                        # Веб-панель (React + TypeScript)
│   ├── src/
│   │   ├── api/                  # API-клиент (axios, auth, events, rules)
│   │   ├── components/           # React-компоненты
│   │   │   ├── common/           # Общие компоненты (Badge, EmptyState и др.)
│   │   │   ├── layout/           # Layout (AppShell, Header, Sidebar)
│   │   │   └── ui/               # shadcn/ui компоненты
│   │   ├── hooks/                # React-хуки (useDashboard, useEvents, useRules)
│   │   ├── pages/                # Страницы (Dashboard, Events, Rules, Login)
│   │   ├── store/                # Zustand stores (auth, filters)
│   │   └── router.tsx            # React Router конфигурация
│   ├── package.json
│   └── vite.config.ts
├── teststand/                    # Тестовое приложение (Go)
│   ├── main.go
│   ├── handlers.go
│   ├── db.go
│   ├── templates/
│   └── Dockerfile
├── docker-compose.yml            # Конфигурация для разработки
└── docker-compose.prod.yml       # Продакшен-оверрайды
```

### Входные точки в программу

> Расположение входных точек в программу.

| Компонент | Входная точка | Описание |
|-----------|---------------|----------|
| WAF Proxy | `waf/cmd/waf/main.go` | Основной сервис: reverse-proxy, admin API, metrics server |
| Teststand | `teststand/main.go` | Тестовое веб-приложение |
| Panel | `panel/src/main.tsx` | React SPA, точка входа для Vite |

### Алгоритмы запуска ПО для отладки

1. **Запуск инфраструктуры и WAF через docker-compose:**

Для разработки

```bash
docker-compose up --build -d
```

Как в прод стенде

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file ./.env.prod.example up -d
```

Это поднимет все сервисы: teststand-db, teststand-app, clickhouse, waf-postgres, waf.

2. **Запуск панели в режиме разработки:**

```bash
cd panel
npm install
npm run dev
```

Панель будет доступна на `http://localhost:5173`.

3. **Запуск WAF локально (без Docker):**

```bash
cd waf
go run ./cmd/waf
```

Требуется предварительно запустить ClickHouse и PostgreSQL.

4. **Запуск тестов:**

```bash
# WAF тесты
cd waf && go test ./...

# Panel тесты
cd panel && npm test
```

### Руководство по настройке и запуску дистрибутива ПО

> Требования: `docs/DEPLOY`.

Подробное руководство по настройке и запуску находится в `docs/4_DEPLOY.md`.

## 4 Требования к аппаратному обеспечению

> Обеспечение, необходимое для запуска: параметры технических средств для запуска ПО с указанием, на какие функции накладываются ограничения производительности.

| Параметр | Минимальное значение | Рекомендуемое значение | Ограничения |
|----------|---------------------|----------------------|-------------|
| CPU | 2 ядра | 4 ядра | При высоком RPS детекция (regex-matching) создаёт основную нагрузку на CPU |
| RAM | 2 ГБ | 4 ГБ | ClickHouse требует минимум 1 ГБ для аналитических запросов |
| Диск | 5 ГБ | 20 ГБ | Объём зависит от количества событий; ClickHouse использует сжатие |
| Сеть | 100 Мбит/с | 1 Гбит/с | Пропускная способность прокси ограничена сетевым каналом |
| Docker | Docker Engine 20.x+ | Docker Engine 24.x+ | Требуется docker-compose v2 |

## 5 Безопасность системы

> Требования: `docs/SECURITY`

Подробный анализ безопасности системы находится в `docs/5_SECURITY.md`.
