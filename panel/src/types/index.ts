export type Verdict = "allow" | "block" | "log_only"
export type RuleType = "regex" | "heuristic"
export type RuleCategory = "sqli" | "xss"
export type UserRole = "admin" | "analyst"

export interface Event {
  EventID: string
  Timestamp: number
  RequestID: string
  ClientIP: string
  Host: string
  Method: string
  Path: string
  NormalizedPath: string
  Verdict: Verdict
  StatusCode: number
  LatencyMs: number
  RawQuery: string
  NormalizedQuery: string
  RawBody: string
  NormalizedBody: string
  QueryParams: string
  BodyParams: string
  Headers: string
  Cookies: string
  UserAgent: string
  ContentType: string
  Referer: string
  BodyTruncated: 0 | 1
  BodySize: number
  RuleIDs: string[]
  Score: number
}

export interface Rule {
  ID: string
  Name: string
  Type: RuleType
  Category: RuleCategory
  Pattern: string
  Heuristic: string
  Threshold: number
  Targets: string[]
  Weight: number
  Enabled: boolean
  LogOnly: boolean
}

export type RuleRequest = Omit<Rule, "ID">

export interface EventFilter {
  from?: string
  to?: string
  ip?: string
  verdict?: Verdict
  rule_id?: string
  limit?: number
  offset?: number
}

export interface PaginatedEvents {
  data: Event[]
  total: number
  offset: number
  limit: number
}

export interface ExportFilter {
  from?: string
  to?: string
  ip?: string
  verdict?: Verdict
  rule_id?: string
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  expires_at: string
}

export interface AuthState {
  token: string | null
  role: UserRole | null
  username: string | null
  expiresAt: string | null
}
