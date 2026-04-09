import { apiClient } from "@/api/client"
import type { Event, EventFilter, ExportFilter, PaginatedEvents } from "@/types"

function compactParams<T extends object>(params: T): Record<string, unknown> {
  const entries = Object.entries(params as Record<string, unknown>)
  return Object.fromEntries(entries.filter(([, value]) => value !== undefined && value !== null && value !== ""))
}

export async function getEvents(filter: EventFilter): Promise<PaginatedEvents> {
  const response = await apiClient.get<PaginatedEvents>("/api/events", {
    params: compactParams(filter),
  })

  return response.data
}

export async function exportEvents(filter: ExportFilter): Promise<Event[]> {
  const response = await apiClient.post<Event[]>("/api/events/export", compactParams(filter))
  return response.data
}
