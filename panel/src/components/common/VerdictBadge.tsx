import { Badge } from "@/components/ui/badge"
import type { Verdict } from "@/types"

interface VerdictBadgeProps {
  verdict: Verdict
}

export function VerdictBadge({ verdict }: VerdictBadgeProps) {
  if (verdict === "block") {
    return <Badge variant="destructive">block</Badge>
  }

  if (verdict === "allow") {
    return (
      <Badge variant="outline" className="text-green-600">
        allow
      </Badge>
    )
  }

  return (
    <Badge variant="secondary" className="text-amber-500">
      log_only
    </Badge>
  )
}
