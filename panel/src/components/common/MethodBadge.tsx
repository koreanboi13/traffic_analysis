import { Badge } from "@/components/ui/badge"

interface MethodBadgeProps {
  method: string
}

export function MethodBadge({ method }: MethodBadgeProps) {
  const normalized = method.toUpperCase()

  if (normalized === "GET") {
    return <Badge variant="outline">GET</Badge>
  }

  if (normalized === "POST" || normalized === "PUT") {
    return <Badge variant="secondary">{normalized}</Badge>
  }

  if (normalized === "DELETE") {
    return <Badge variant="destructive">DELETE</Badge>
  }

  return <Badge>{normalized}</Badge>
}
