import { Link, useLocation, useNavigate } from "react-router-dom"
import { LayoutDashboard, List, LogOut, Shield } from "lucide-react"

import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { useAuthStore } from "@/store/authStore"

const navItems = [
  { label: "Dashboard", to: "/dashboard", icon: LayoutDashboard },
  { label: "Events", to: "/events", icon: List },
  { label: "Rules", to: "/rules", icon: Shield },
]

export function Sidebar() {
  const location = useLocation()
  const navigate = useNavigate()
  const username = useAuthStore((state) => state.username)
  const clearAuth = useAuthStore((state) => state.clearAuth)

  const isActive = (to: string) => {
    if (to === "/events") {
      return location.pathname === "/events" || location.pathname.startsWith("/events/")
    }

    return location.pathname === to
  }

  const handleLogout = () => {
    clearAuth()
    navigate("/login", { replace: true })
  }

  return (
    <aside className="fixed left-0 top-0 flex h-screen w-[240px] flex-col border-r border-zinc-800 bg-zinc-950 px-4 py-6">
      <div className="mb-8 flex items-center gap-3 px-1">
        <Shield className="size-8 text-blue-600" />
        <span className="text-lg font-semibold text-zinc-100">WAF Panel</span>
      </div>

      <nav className="space-y-2">
        {navItems.map(({ label, to, icon: Icon }) => (
          <Link
            key={to}
            to={to}
            className={cn(
              "flex h-10 items-center gap-3 rounded-md px-3 text-sm font-medium transition-colors",
              isActive(to)
                ? "bg-blue-600 text-white"
                : "text-zinc-400 hover:bg-zinc-700 hover:text-zinc-100",
            )}
          >
            <Icon className="size-4" />
            <span>{label}</span>
          </Link>
        ))}
      </nav>

      <div className="mt-auto border-t border-zinc-800 pt-4">
        <p className="mb-3 truncate text-sm text-zinc-400">{username ?? "unknown user"}</p>
        <Button variant="ghost" className="h-10 w-full justify-start gap-3 text-zinc-300" onClick={handleLogout}>
          <LogOut className="size-4" />
          <span>Logout</span>
        </Button>
      </div>
    </aside>
  )
}
