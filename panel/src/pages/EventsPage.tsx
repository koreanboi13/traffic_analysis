import { useMemo, useState } from "react"
import { ExternalLink } from "lucide-react"
import { useNavigate } from "react-router-dom"

import { Header } from "@/components/layout/Header"
import { EmptyState } from "@/components/common/EmptyState"
import { ErrorState } from "@/components/common/ErrorState"
import { MethodBadge } from "@/components/common/MethodBadge"
import { VerdictBadge } from "@/components/common/VerdictBadge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { formatScore, formatTimestamp, truncate } from "@/lib/formatters"
import { useFilterStore } from "@/store/filterStore"
import { useEvents } from "@/hooks/useEvents"
import type { Event, EventFilter, Verdict } from "@/types"

const PAGE_SIZE = 20

interface FilterFormState {
  from: string
  to: string
  ip: string
  verdict: "all" | Verdict
  ruleId: string
}

function toDateTimeLocal(value?: string): string {
  if (!value) {
    return ""
  }

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return ""
  }

  const offset = date.getTimezoneOffset()
  const localDate = new Date(date.getTime() - offset * 60_000)
  return localDate.toISOString().slice(0, 16)
}

function toRfc3339(value: string): string | undefined {
  if (!value) {
    return undefined
  }

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return undefined
  }

  return date.toISOString()
}

function buildInitialForm(filter: EventFilter): FilterFormState {
  return {
    from: toDateTimeLocal(filter.from),
    to: toDateTimeLocal(filter.to),
    ip: filter.ip ?? "",
    verdict: filter.verdict ?? "all",
    ruleId: filter.rule_id ?? "",
  }
}

export function EventsPage() {
  const navigate = useNavigate()
  const filter = useFilterStore((state) => state.filter)
  const setFilter = useFilterStore((state) => state.setFilter)
  const resetFilter = useFilterStore((state) => state.resetFilter)

  const [form, setForm] = useState<FilterFormState>(() => buildInitialForm(filter))
  const { data, isLoading, isError, refetch, isFetching } = useEvents(filter)

  const currentPage = Math.floor((filter.offset ?? 0) / PAGE_SIZE) + 1
  const totalPages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE))

  const hasPrevious = currentPage > 1
  const hasNext = currentPage < totalPages

  const events = useMemo(() => data?.data ?? [], [data?.data])

  const applyFilters = () => {
    setFilter({
      from: toRfc3339(form.from),
      to: toRfc3339(form.to),
      ip: form.ip.trim() || undefined,
      verdict: form.verdict === "all" ? undefined : form.verdict,
      rule_id: form.ruleId.trim() || undefined,
      limit: PAGE_SIZE,
      offset: 0,
    })
  }

  const resetFilters = () => {
    resetFilter()
    setForm({
      from: "",
      to: "",
      ip: "",
      verdict: "all",
      ruleId: "",
    })
  }

  const openEvent = (event: Event) => {
    navigate(`/events/${event.EventID}`, { state: { event } })
  }

  return (
    <section>
      <Header title="Events" />

      <div className="space-y-6 px-8 py-6">
        <div className="flex flex-wrap items-end gap-3 rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="min-w-52 space-y-2">
            <label className="text-xs text-zinc-400">Date from</label>
            <Input
              type="datetime-local"
              value={form.from}
              onChange={(event) => setForm((prev) => ({ ...prev, from: event.target.value }))}
            />
          </div>
          <div className="min-w-52 space-y-2">
            <label className="text-xs text-zinc-400">Date to</label>
            <Input
              type="datetime-local"
              value={form.to}
              onChange={(event) => setForm((prev) => ({ ...prev, to: event.target.value }))}
            />
          </div>
          <div className="min-w-44 space-y-2">
            <label className="text-xs text-zinc-400">IP</label>
            <Input
              type="text"
              placeholder="e.g. 192.168.1.1"
              value={form.ip}
              onChange={(event) => setForm((prev) => ({ ...prev, ip: event.target.value }))}
            />
          </div>
          <div className="min-w-44 space-y-2">
            <label className="text-xs text-zinc-400">Verdict</label>
            <Select value={form.verdict} onValueChange={(value) => setForm((prev) => ({ ...prev, verdict: value as FilterFormState["verdict"] }))}>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="All verdicts" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All verdicts</SelectItem>
                <SelectItem value="allow">Allow</SelectItem>
                <SelectItem value="block">Block</SelectItem>
                <SelectItem value="log_only">Log Only</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="min-w-40 space-y-2">
            <label className="text-xs text-zinc-400">Rule ID</label>
            <Input
              type="text"
              placeholder="Rule ID"
              value={form.ruleId}
              onChange={(event) => setForm((prev) => ({ ...prev, ruleId: event.target.value }))}
            />
          </div>
          <Button className="bg-blue-600 text-white hover:bg-blue-500" onClick={applyFilters}>
            Apply Filters
          </Button>
          <Button variant="outline" onClick={resetFilters}>
            Reset Filters
          </Button>
        </div>

        {isLoading || isFetching ? (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((_, index) => (
                <Skeleton key={index} className="h-10 w-full bg-zinc-800" />
              ))}
            </div>
          </div>
        ) : null}

        {!isLoading && isError ? (
          <ErrorState
            message="Could not connect to WAF API"
            detail="Check that the proxy service is running on port 8090."
            onRetry={() => {
              void refetch()
            }}
          />
        ) : null}

        {!isLoading && !isError && events.length === 0 ? (
          <EmptyState
            heading="No events found"
            body="Try adjusting your filters or expanding the time range."
          />
        ) : null}

        {!isLoading && !isError && events.length > 0 ? (
          <div className="space-y-4">
            <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900">
              <TooltipProvider>
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead style={{ width: 180 }}>Timestamp</TableHead>
                      <TableHead style={{ width: 130 }}>IP</TableHead>
                      <TableHead style={{ width: 70 }}>Method</TableHead>
                      <TableHead>Path</TableHead>
                      <TableHead style={{ width: 90 }}>Verdict</TableHead>
                      <TableHead className="text-right" style={{ width: 70 }}>
                        Score
                      </TableHead>
                      <TableHead style={{ width: 48 }}>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {events.map((event) => (
                      <TableRow
                        key={event.EventID}
                        className="cursor-pointer border-zinc-800 hover:bg-zinc-800/50"
                        onClick={() => openEvent(event)}
                      >
                        <TableCell className="font-mono text-xs text-zinc-300">
                          {formatTimestamp(event.Timestamp)}
                        </TableCell>
                        <TableCell>{event.ClientIP}</TableCell>
                        <TableCell>
                          <MethodBadge method={event.Method} />
                        </TableCell>
                        <TableCell title={event.Path}>{truncate(event.Path, 40)}</TableCell>
                        <TableCell>
                          <VerdictBadge verdict={event.Verdict} />
                        </TableCell>
                        <TableCell className="text-right">{formatScore(event.Score)}</TableCell>
                        <TableCell>
                          <Tooltip>
                            <TooltipTrigger render={<span />}>
                              <Button
                                variant="ghost"
                                size="icon-sm"
                                onClick={(clickEvent) => {
                                  clickEvent.stopPropagation()
                                  openEvent(event)
                                }}
                                aria-label="View event details"
                              >
                                <ExternalLink className="size-4" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>View event details</TooltipContent>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TooltipProvider>
            </div>

            <div className="flex items-center justify-between">
              <p className="text-sm text-zinc-400">
                Page {currentPage} of {totalPages}
              </p>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  disabled={!hasPrevious}
                  onClick={() => setFilter({ offset: Math.max(0, (filter.offset ?? 0) - PAGE_SIZE), limit: PAGE_SIZE })}
                >
                  Prev
                </Button>
                <Button
                  variant="outline"
                  disabled={!hasNext}
                  onClick={() => setFilter({ offset: (filter.offset ?? 0) + PAGE_SIZE, limit: PAGE_SIZE })}
                >
                  Next
                </Button>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </section>
  )
}
