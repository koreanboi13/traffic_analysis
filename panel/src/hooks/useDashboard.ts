import { useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { format, subDays, subHours } from "date-fns"

import { getEvents } from "@/api/events"

export type DashboardPreset = "1h" | "6h" | "24h" | "7d"

export interface DashboardData {
  totalRequests: number
  blocked: number
  blockRate: string
  logOnly: number
  timeSeries: Array<{ label: string; blocked: number; timestamp: number }>
  topRules: Array<{ name: string; count: number }>
  topPaths: Array<{ name: string; count: number }>
}

function getStartDate(preset: DashboardPreset): Date {
  const now = new Date()

  switch (preset) {
    case "1h":
      return subHours(now, 1)
    case "6h":
      return subHours(now, 6)
    case "24h":
      return subHours(now, 24)
    case "7d":
      return subDays(now, 7)
  }
}

function getBucketSizeMs(preset: DashboardPreset): number {
  switch (preset) {
    case "1h":
    case "6h":
      return 5 * 60 * 1000
    case "24h":
      return 60 * 60 * 1000
    case "7d":
      return 6 * 60 * 60 * 1000
  }
}

function getLabel(ts: number, preset: DashboardPreset): string {
  if (preset === "7d") {
    return format(ts, "MMM d")
  }

  return format(ts, "HH:mm")
}

export function useDashboard(preset: DashboardPreset) {
  const from = useMemo(() => getStartDate(preset).toISOString(), [preset])

  const query = useQuery({
    queryKey: ["dashboard", preset, from],
    queryFn: () =>
      getEvents({
        from,
        limit: 1000,
        offset: 0,
      }),
    refetchInterval: 30000,
  })

  const data = useMemo<DashboardData>(() => {
    const events = query.data?.data ?? []

    const totalRequests = events.length
    const blocked = events.filter((event) => event.Verdict === "block").length
    const logOnly = events.filter((event) => event.Verdict === "log_only").length
    const blockRate = totalRequests === 0 ? "0.0" : ((blocked / totalRequests) * 100).toFixed(1)

    const bucketSize = getBucketSizeMs(preset)
    const startDate = getStartDate(preset)
    const start = Math.floor(startDate.getTime() / bucketSize) * bucketSize
    const end = Math.floor(Date.now() / bucketSize) * bucketSize

    const blockedByBucket = new Map<number, number>()
    for (const event of events) {
      if (event.Verdict !== "block") {
        continue
      }
      const bucket = Math.floor(event.Timestamp / bucketSize) * bucketSize
      blockedByBucket.set(bucket, (blockedByBucket.get(bucket) ?? 0) + 1)
    }

    const timeSeries: DashboardData["timeSeries"] = []
    for (let ts = start; ts <= end; ts += bucketSize) {
      timeSeries.push({
        label: getLabel(ts, preset),
        blocked: blockedByBucket.get(ts) ?? 0,
        timestamp: ts,
      })
    }

    const topRulesMap = new Map<string, number>()
    for (const event of events) {
      for (const ruleID of event.RuleIDs) {
        topRulesMap.set(ruleID, (topRulesMap.get(ruleID) ?? 0) + 1)
      }
    }
    const topRules = Array.from(topRulesMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, count]) => ({ name, count }))

    const topPathsMap = new Map<string, number>()
    for (const event of events) {
      if (event.Verdict !== "block") {
        continue
      }
      topPathsMap.set(event.Path, (topPathsMap.get(event.Path) ?? 0) + 1)
    }
    const topPaths = Array.from(topPathsMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, count]) => ({ name, count }))

    return {
      totalRequests,
      blocked,
      blockRate,
      logOnly,
      timeSeries,
      topRules,
      topPaths,
    }
  }, [preset, query.data?.data])

  return {
    data,
    isLoading: query.isLoading,
    isError: query.isError,
    refetch: query.refetch,
    isFetching: query.isFetching,
  }
}
