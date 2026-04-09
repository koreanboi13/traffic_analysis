import { Outlet } from "react-router-dom"

import { Sidebar } from "@/components/layout/Sidebar"

export function AppShell() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <Sidebar />
      <main className="ml-[240px] min-h-screen">
        <Outlet />
      </main>
    </div>
  )
}
