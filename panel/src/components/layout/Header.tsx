import type { ReactNode } from "react"

interface HeaderProps {
  title: string
  actions?: ReactNode
}

export function Header({ title, actions }: HeaderProps) {
  return (
    <header className="flex items-center justify-between border-b border-zinc-800 px-8 py-4">
      <h1 className="text-2xl font-semibold text-zinc-100">{title}</h1>
      <div>{actions}</div>
    </header>
  )
}
