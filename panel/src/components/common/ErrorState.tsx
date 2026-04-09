import { AlertTriangle } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

interface ErrorStateProps {
  message: string
  detail?: string
  onRetry?: () => void
}

export function ErrorState({ message, detail, onRetry }: ErrorStateProps) {
  return (
    <div className="flex min-h-[320px] items-center justify-center px-8">
      <Card className="w-full max-w-xl bg-zinc-900 ring-zinc-800">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-red-400">
            <AlertTriangle className="size-5" />
            <span>{message}</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {detail ? <p className="text-zinc-400">{detail}</p> : null}
          {onRetry ? (
            <Button variant="outline" onClick={onRetry}>
              Retry
            </Button>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}
