# Описание проекта системы
## Структура ПО
> Перечень программных компонентов (разрабатываемых и используемых) с указанием роли в системе. 

1. **WAF Reverse-Proxy** — сервис на языке Go 1.25, реализующий обратный прокси-сервер с middleware-цепочкой анализа трафика (parse → normalize → detect → decision). Использует `net/http/httputil.ReverseProxy` для проксирования и `go-chi/chi/v5` для маршрутизации Admin API.
2. **Admin API** — REST API на Go (встроен в WAF-сервис), обслуживает управление правилами, аутентификацию (JWT/HS256) и экспорт событий. Порт `:8090`.
3. **Metrics Server** — HTTP-сервер Prometheus-метрик на порту `:9090`. Экспонирует RPS, latency, счётчики блокировок.
4. **Web Panel** — SPA на React 19 + TypeScript 6, собирается с помощью Vite 8. Использует shadcn/ui, Tailwind CSS v4, TanStack Query v5, React Router v7, Zustand v5, Recharts v3.
5. **ClickHouse** v25.x — колоночная СУБД для хранения и аналитики событий WAF. Нативный протокол (порт 9000).
6. **PostgreSQL** v16 — реляционная СУБД для хранения правил детекции и учётных записей пользователей панели.
7. **Teststand** — тестовое веб-приложение на Go с собственной PostgreSQL-базой, выступающее в роли защищаемого backend-сервиса.

## Структурная схема ПО в нотации C4
### Уровень контекста

```
┌─────────────┐     HTTPS/HTTP      ┌──────────────────────┐     HTTP      ┌──────────────┐
│             │ ──────────────────►  │                      │ ───────────►  │              │
│  Клиент     │                     │  Traffic Analysis    │              │  Teststand   │
│  (Браузер)  │ ◄──────────────────  │  WAF System          │ ◄───────────  │  (Backend)   │
│             │     Ответ / 403     │                      │   Ответ      │              │
└─────────────┘                     └──────────────────────┘              └──────────────┘
                                             │
                                    ┌────────┴────────┐
                                    ▼                 ▼
                             ┌────────────┐    ┌───────────┐
                             │ Admin      │    │ Analyst   │
                             │ (Браузер)  │    │ (Браузер) │
                             └────────────┘    └───────────┘
```

Система Traffic Analysis WAF принимает HTTP-трафик от клиентов, анализирует его на наличие атак и проксирует к защищаемому приложению (Teststand). Администраторы и аналитики взаимодействуют с системой через веб-панель.

### Уровень контейнеров

```
┌───────────────────────────────────────────────────────────────────────┐
│                        Traffic Analysis WAF System                    │
│                                                                       │
│  ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐  │
│  │  WAF Proxy        │   │  Admin API        │   │  Metrics Server  │  │
│  │  :8080            │   │  :8090            │   │  :9090           │  │
│  │  Go / httputil    │   │  Go / chi         │   │  Go / prometheus │  │
│  └────────┬─────────┘   └────────┬─────────┘   └──────────────────┘  │
│           │                      │                                    │
│           ▼                      ▼                                    │
│  ┌──────────────────┐   ┌──────────────────┐                         │
│  │  ClickHouse       │   │  PostgreSQL       │                        │
│  │  :9000 (native)   │   │  :5432            │                        │
│  │  События WAF      │   │  Правила, Users   │                        │
│  └──────────────────┘   └──────────────────┘                         │
│                                                                       │
│  ┌──────────────────┐                                                 │
│  │  Web Panel (SPA)  │                                                │
│  │  React 19 + TS    │                                                │
│  │  Vite dev :5173   │                                                │
│  └──────────────────┘                                                 │
└───────────────────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│  Teststand        │
│  Go :8888         │
│  + PostgreSQL     │
└──────────────────┘
```

## Схемы баз данных (ERD)
### PostgreSQL (WAF)

```
┌─────────────────────────────┐
│           users             │
├─────────────────────────────┤
│ id         SERIAL PK       │
│ username   VARCHAR UNIQUE   │
│ password   VARCHAR (bcrypt) │
│ role       VARCHAR          │
│            ("admin"|        │
│             "analyst")      │
│ created_at TIMESTAMP        │
└─────────────────────────────┘

┌─────────────────────────────┐
│           rules             │
├─────────────────────────────┤
│ id         VARCHAR PK       │
│ name       VARCHAR          │
│ type       VARCHAR          │
│            ("regex"|        │
│             "heuristic")    │
│ category   VARCHAR          │
│            ("sqli"|"xss")   │
│ pattern    VARCHAR          │
│ heuristic  VARCHAR          │
│ threshold  FLOAT            │
│ targets    TEXT[]            │
│ weight     FLOAT            │
│ enabled    BOOLEAN          │
│ log_only   BOOLEAN          │
└─────────────────────────────┘
```

### ClickHouse (Events)

```
┌──────────────────────────────────┐
│           waf.events             │
├──────────────────────────────────┤
│ event_id         UUID            │
│ timestamp        Int64           │
│ request_id       String          │
│ client_ip        String          │
│ host             String          │
│ method           String          │
│ path             String          │
│ normalized_path  String          │
│ verdict          String          │
│ status_code      UInt16          │
│ latency_ms       Float32         │
│ raw_query        String          │
│ normalized_query String          │
│ raw_body         String          │
│ normalized_body  String          │
│ query_params     String (JSON)   │
│ body_params      String (JSON)   │
│ headers          String (JSON)   │
│ cookies          String (JSON)   │
│ user_agent       String          │
│ content_type     String          │
│ referer          String          │
│ body_truncated   UInt8           │
│ body_size        UInt32          │
│ rule_ids         Array(String)   │
│ score            Float32         │
└──────────────────────────────────┘
```

## Функциональная схема ПО

> Схема потоков данных и функций в нотации логической DFD-диаграммы (data flow diagram). 

```
                          HTTP-запрос
                              │
                              ▼
                    ┌──────────────────┐
                    │   1. Parse       │
                    │   Извлечение     │
                    │   метаданных     │
                    └────────┬─────────┘
                             │
                    ParsedRequest (method, URI, query,
                    headers, cookies, body, IP, UA)
                             │
                             ▼
                    ┌──────────────────┐
                    │  2. Normalize    │
                    │  URL-decode,     │
                    │  lower-case,     │
                    │  path-normalize  │
                    └────────┬─────────┘
                             │
                    NormalizedRequest (+ normalized_path,
                    normalized_query, normalized_body)
                             │
                             ▼
                    ┌──────────────────┐
                    │  3. Allowlist    │──── IP/Path match ──► ALLOW (bypass)
                    │  Check           │
                    └────────┬─────────┘
                             │ не в allowlist
                             ▼
                    ┌──────────────────┐
                    │  4. Detect       │
                    │  Regex rules +   │
                    │  Heuristic rules │
                    └────────┬─────────┘
                             │
                    EvaluationResult (score, matched_rules,
                    verdict: allow/log_only/block)
                             │
                             ▼
                    ┌──────────────────┐
                    │  5. Decision     │
                    │  score < log_th  │──► ALLOW ──► Proxy to backend
                    │  score ≥ log_th  │──► LOG_ONLY ──► Proxy + log event
                    │  score ≥ block_th│──► BLOCK ──► 403 + log event
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │  6. Record Event │
                    │  Batch write to  │
                    │  ClickHouse      │
                    └──────────────────┘
```
