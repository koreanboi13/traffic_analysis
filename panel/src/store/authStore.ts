import { create } from "zustand"
import type { AuthState, UserRole } from "@/types"

const STORAGE_KEY = "waf.auth"

interface AuthStore extends AuthState {
  setAuth: (
    token: string,
    role: UserRole | null,
    username: string | null,
    expiresAt: string,
  ) => void
  clearAuth: () => void
}

interface JwtPayload {
  sub?: string
  role?: UserRole
  exp?: number
}

function decodeJwtPayload(token: string): JwtPayload | null {
  try {
    const payloadPart = token.split(".")[1]
    if (!payloadPart) {
      return null
    }

    const normalized = payloadPart.replace(/-/g, "+").replace(/_/g, "/")
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")
    const decoded = atob(padded)

    return JSON.parse(decoded) as JwtPayload
  } catch {
    return null
  }
}

function getInitialState(): AuthState {
  if (typeof window === "undefined") {
    return {
      token: null,
      role: null,
      username: null,
      expiresAt: null,
    }
  }

  const raw = window.localStorage.getItem(STORAGE_KEY)
  if (!raw) {
    return {
      token: null,
      role: null,
      username: null,
      expiresAt: null,
    }
  }

  try {
    const parsed = JSON.parse(raw) as { token: string; expiresAt: string }
    const payload = decodeJwtPayload(parsed.token)
    const nowSec = Math.floor(Date.now() / 1000)

    if (!payload?.exp || payload.exp <= nowSec) {
      window.localStorage.removeItem(STORAGE_KEY)
      return {
        token: null,
        role: null,
        username: null,
        expiresAt: null,
      }
    }

    return {
      token: parsed.token,
      role: payload.role ?? null,
      username: payload.sub ?? null,
      expiresAt: parsed.expiresAt,
    }
  } catch {
    window.localStorage.removeItem(STORAGE_KEY)
    return {
      token: null,
      role: null,
      username: null,
      expiresAt: null,
    }
  }
}

const initialState = getInitialState()

export const useAuthStore = create<AuthStore>((set) => ({
  ...initialState,
  setAuth: (token, role, username, expiresAt) => {
    const nextState: AuthState = {
      token,
      role,
      username,
      expiresAt,
    }

    if (typeof window !== "undefined") {
      window.localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({ token: nextState.token, expiresAt: nextState.expiresAt }),
      )
    }

    set(nextState)
  },
  clearAuth: () => {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(STORAGE_KEY)
    }

    set({
      token: null,
      role: null,
      username: null,
      expiresAt: null,
    })
  },
}))
