import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

interface EmptyStateProps {
  heading: string
  body: string
}

export function EmptyState({ heading, body }: EmptyStateProps) {
  return (
    <div className="flex min-h-[320px] items-center justify-center px-8">
      <Card className="w-full max-w-xl bg-zinc-900 ring-zinc-800">
        <CardHeader>
          <CardTitle className="text-zinc-100">{heading}</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-zinc-400">{body}</p>
        </CardContent>
      </Card>
    </div>
  )
}
