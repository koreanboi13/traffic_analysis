import { cn } from "@/lib/utils"

interface LogOnlyToggleProps {
  enabled: boolean
  logOnly: boolean
  onToggle: (enabled: boolean, logOnly: boolean) => void
  disabled?: boolean
}

function getState(enabled: boolean, logOnly: boolean): {
  label: string
  className: string
  next: { enabled: boolean; logOnly: boolean }
} {
  if (!enabled) {
    return {
      label: "Disabled",
      className: "bg-zinc-600 text-white",
      next: { enabled: true, logOnly: false },
    }
  }

  if (logOnly) {
    return {
      label: "Log Only",
      className: "bg-amber-500 text-black",
      next: { enabled: false, logOnly: false },
    }
  }

  return {
    label: "Enabled",
    className: "bg-blue-600 text-white",
    next: { enabled: true, logOnly: true },
  }
}

export function LogOnlyToggle({ enabled, logOnly, onToggle, disabled = false }: LogOnlyToggleProps) {
  const state = getState(enabled, logOnly)

  return (
    <button
      type="button"
      className={cn(
        "inline-flex h-7 min-w-20 items-center justify-center rounded-full px-3 text-xs font-medium transition",
        state.className,
        disabled ? "cursor-not-allowed opacity-60" : "cursor-pointer",
      )}
      onClick={() => {
        if (disabled) {
          return
        }
        onToggle(state.next.enabled, state.next.logOnly)
      }}
      disabled={disabled}
    >
      {state.label}
    </button>
  )
}
