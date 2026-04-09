import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { RouterProvider } from "react-router-dom"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { login } from "@/api/auth"
import { createAppRouter } from "@/router"
import { useAuthStore } from "@/store/authStore"

vi.mock("@/api/auth", () => ({
  login: vi.fn(),
}))

const mockedLogin = vi.mocked(login)

function makeJwt(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: "none", typ: "JWT" }))
  const body = btoa(JSON.stringify(payload))
  return `${header}.${body}.signature`
}

function renderAt(pathname: string) {
  window.history.pushState({}, "", pathname)
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

  return render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={createAppRouter()} />
    </QueryClientProvider>,
  )
}

describe("auth flow", () => {
  beforeEach(() => {
    mockedLogin.mockReset()
    window.localStorage.clear()
    useAuthStore.getState().clearAuth()
  })

  it("redirects unauthenticated user to /login", async () => {
    renderAt("/dashboard")

    expect(await screen.findByRole("button", { name: "Sign in" })).toBeInTheDocument()
  })

  it("shows sidebar navigation after successful login", async () => {
    mockedLogin.mockResolvedValue({
      token: makeJwt({ sub: "analyst1", role: "analyst", exp: Math.floor(Date.now() / 1000) + 3600 }),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
    })

    const user = userEvent.setup()
    renderAt("/login")

    await user.type(screen.getByPlaceholderText("Username"), "analyst1")
    await user.type(screen.getByPlaceholderText("Password"), "secret")
    await user.click(screen.getByRole("button", { name: "Sign in" }))

    expect(await screen.findByRole("link", { name: "Dashboard" })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Events" })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Rules" })).toBeInTheDocument()
  })

  it("clears token and returns to /login on logout", async () => {
    const token = makeJwt({ sub: "admin1", role: "admin", exp: Math.floor(Date.now() / 1000) + 3600 })
    useAuthStore.getState().setAuth(token, "admin", "admin1", new Date(Date.now() + 3600_000).toISOString())

    const user = userEvent.setup()
    renderAt("/dashboard")

    await user.click(await screen.findByRole("button", { name: "Logout" }))

    await waitFor(() => {
      expect(useAuthStore.getState().token).toBeNull()
    })
    expect(await screen.findByRole("button", { name: "Sign in" })).toBeInTheDocument()
  })
})
