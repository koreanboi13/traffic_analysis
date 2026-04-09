import { useMemo, useState } from "react"
import axios from "axios"
import { Navigate, useNavigate } from "react-router-dom"
import { Loader2, Shield } from "lucide-react"

import { login } from "@/api/auth"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useAuthStore } from "@/store/authStore"
import type { UserRole } from "@/types"

interface JwtPayload {
  sub?: string
  role?: UserRole
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

export function LoginPage() {
  const navigate = useNavigate()
  const token = useAuthStore((state) => state.token)
  const setAuth = useAuthStore((state) => state.setAuth)

  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  const isDisabled = useMemo(
    () => isSubmitting || username.trim().length === 0 || password.length === 0,
    [isSubmitting, password.length, username],
  )

  if (token) {
    return <Navigate to="/dashboard" replace />
  }

  const onSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setErrorMessage(null)
    setIsSubmitting(true)

    try {
      const response = await login({
        username: username.trim(),
        password,
      })

      const payload = decodeJwtPayload(response.token)
      setAuth(response.token, payload?.role ?? null, payload?.sub ?? null, response.expires_at)
      navigate("/dashboard", { replace: true })
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (!error.response) {
          setErrorMessage("Could not connect to WAF API")
        } else if (error.response.status === 401) {
          setErrorMessage("Invalid credentials")
        } else {
          setErrorMessage("Login failed")
        }
      } else {
        setErrorMessage("Login failed")
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 px-4">
      <div className="w-full max-w-[400px] rounded-xl border border-zinc-800 bg-zinc-900 p-6 shadow-2xl">
        <div className="mb-6 flex items-center gap-3">
          <Shield className="size-8 text-blue-600" />
          <h2 className="text-2xl font-semibold text-zinc-100">WAF Panel</h2>
        </div>

        <form className="space-y-4" onSubmit={onSubmit}>
          <Input
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder="Username"
            autoComplete="username"
            disabled={isSubmitting}
          />
          <Input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Password"
            autoComplete="current-password"
            disabled={isSubmitting}
          />

          <Button type="submit" className="h-10 w-full bg-blue-600 text-white hover:bg-blue-500" disabled={isDisabled}>
            {isSubmitting ? <Loader2 className="size-4 animate-spin" /> : "Sign in"}
          </Button>

          {errorMessage ? <p className="text-sm text-red-400">{errorMessage}</p> : null}
        </form>
      </div>
    </div>
  )
}
