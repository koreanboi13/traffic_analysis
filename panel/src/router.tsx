import { createBrowserRouter, Navigate } from "react-router-dom"
import type { ReactNode } from "react"

import { AppShell } from "@/components/layout/AppShell"
import { useAuthStore } from "@/store/authStore"
import { DashboardPage } from "@/pages/DashboardPage"
import { EventDetailPage } from "@/pages/EventDetailPage"
import { EventsPage } from "@/pages/EventsPage"
import { LoginPage } from "@/pages/LoginPage"
import { RulesPage } from "@/pages/RulesPage"

export function RequireAuth({ children }: { children: ReactNode }) {
  const token = useAuthStore((state) => state.token)

  if (!token) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

export function createAppRouter() {
  return createBrowserRouter([
    {
      path: "/",
      element: <Navigate to="/dashboard" replace />,
    },
    {
      path: "/login",
      element: <LoginPage />,
    },
    {
      path: "/",
      element: (
        <RequireAuth>
          <AppShell />
        </RequireAuth>
      ),
      children: [
        {
          path: "dashboard",
          element: <DashboardPage />,
        },
        {
          path: "events",
          element: <EventsPage />,
        },
        {
          path: "events/:id",
          element: <EventDetailPage />,
        },
        {
          path: "rules",
          element: <RulesPage />,
        },
      ],
    },
  ])
}

export const router = createAppRouter()
