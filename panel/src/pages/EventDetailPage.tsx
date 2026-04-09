import { Link, useLocation } from "react-router-dom"

import { Header } from "@/components/layout/Header"
import { MethodBadge } from "@/components/common/MethodBadge"
import { VerdictBadge } from "@/components/common/VerdictBadge"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { formatScore, formatTimestamp } from "@/lib/formatters"
import type { Event } from "@/types"

interface LocationState {
  event?: Event
}

function parseJsonField(value: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(value)
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>
    }
  } catch {
    return null
  }

  return null
}

function renderKeyValues(title: string, rawValue: string) {
  const parsed = parseJsonField(rawValue)

  if (!parsed) {
    return (
      <Card className="bg-zinc-900 ring-zinc-800">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="overflow-x-auto rounded-md bg-zinc-950 p-3 font-mono text-xs text-zinc-300">
            {rawValue || "(empty)"}
          </pre>
        </CardContent>
      </Card>
    )
  }

  const entries = Object.entries(parsed)
  return (
    <Card className="bg-zinc-900 ring-zinc-800">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="text-sm text-zinc-400">(empty)</p>
        ) : (
          <div className="space-y-2">
            {entries.map(([key, value]) => (
              <div key={key} className="grid grid-cols-[180px_1fr] gap-2 text-sm">
                <span className="font-mono text-xs text-zinc-400">{key}</span>
                <span className="break-all text-zinc-200">{String(value)}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export function EventDetailPage() {
  const location = useLocation()
  const state = location.state as LocationState | null
  const event = state?.event

  if (!event) {
    return (
      <section>
        <Header title="Event detail" />
        <div className="px-8 py-6">
          <Card className="max-w-2xl bg-zinc-900 ring-zinc-800">
            <CardHeader>
              <CardTitle>Direct URL access not supported. Return to the Events list and click the event.</CardTitle>
            </CardHeader>
            <CardContent>
              <Link to="/events" className="text-sm text-blue-400 hover:text-blue-300">
                ← Events
              </Link>
            </CardContent>
          </Card>
        </div>
      </section>
    )
  }

  return (
    <section>
      <Header title="Event detail" />
      <div className="space-y-4 px-8 py-6">
        <Link to="/events" className="inline-flex text-sm text-blue-400 hover:text-blue-300">
          ← Events
        </Link>

        <div className="grid gap-4 xl:grid-cols-[3fr_2fr]">
          <div className="space-y-4">
            <Card className="bg-zinc-900 ring-zinc-800">
              <CardHeader>
                <CardTitle>Request metadata</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center gap-3">
                  <MethodBadge method={event.Method} />
                  <span className="font-mono text-sm text-zinc-200">{event.Path}</span>
                </div>
                <div className="grid gap-2 text-sm text-zinc-300 sm:grid-cols-2">
                  <p>
                    <span className="text-zinc-400">Host:</span> {event.Host}
                  </p>
                  <p>
                    <span className="text-zinc-400">Client IP:</span> {event.ClientIP}
                  </p>
                  <p>
                    <span className="text-zinc-400">Timestamp:</span> {formatTimestamp(event.Timestamp)}
                  </p>
                  <p>
                    <span className="text-zinc-400">Status Code:</span> {event.StatusCode}
                  </p>
                  <p>
                    <span className="text-zinc-400">Latency:</span> {formatScore(event.LatencyMs)} ms
                  </p>
                  <p className="font-mono text-xs break-all text-zinc-300">
                    <span className="text-zinc-400">Request ID:</span> {event.RequestID}
                  </p>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-zinc-900 ring-zinc-800">
              <CardHeader>
                <CardTitle>Payload</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="raw">
                  <TabsList>
                    <TabsTrigger value="raw">Raw</TabsTrigger>
                    <TabsTrigger value="normalized">Normalized</TabsTrigger>
                  </TabsList>
                  <TabsContent value="raw" className="space-y-3">
                    {event.BodyTruncated === 1 ? (
                      <div className="rounded-md border border-amber-600/40 bg-amber-950/40 px-3 py-2 text-sm text-amber-300">
                        Request body was truncated for analysis (limit exceeded).
                      </div>
                    ) : null}
                    <pre className="overflow-x-auto rounded-md bg-zinc-950 p-3 font-mono text-xs text-zinc-300">{`RawQuery:\n${event.RawQuery || "(empty)"}\n\nRawBody:\n${event.RawBody || "(empty)"}`}</pre>
                  </TabsContent>
                  <TabsContent value="normalized">
                    <pre className="overflow-x-auto rounded-md bg-zinc-950 p-3 font-mono text-xs text-zinc-300">{`NormalizedPath:\n${event.NormalizedPath || "(empty)"}\n\nNormalizedQuery:\n${event.NormalizedQuery || "(empty)"}\n\nNormalizedBody:\n${event.NormalizedBody || "(empty)"}`}</pre>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>

            {renderKeyValues("Headers", event.Headers)}
            {renderKeyValues("Cookies", event.Cookies)}
          </div>

          <div className="space-y-4">
            <Card className="bg-zinc-900 ring-zinc-800">
              <CardHeader>
                <CardTitle>Detection result</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <VerdictBadge verdict={event.Verdict} />
                </div>
                <p className="text-2xl font-semibold text-zinc-100">Score: {formatScore(event.Score)}</p>
              </CardContent>
            </Card>

            <Card className="bg-zinc-900 ring-zinc-800">
              <CardHeader>
                <CardTitle>Matched Rules</CardTitle>
              </CardHeader>
              <CardContent>
                {event.RuleIDs.length === 0 ? (
                  <p className="text-sm text-zinc-400">No rules matched for this event.</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {event.RuleIDs.map((ruleId) => (
                      <Badge key={ruleId} variant="outline">
                        {ruleId}
                      </Badge>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </section>
  )
}
