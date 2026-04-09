import { useQuery } from "@tanstack/react-query"

import { getEvents } from "@/api/events"
import type { EventFilter } from "@/types"

export function useEvents(filter: EventFilter) {
  return useQuery({
    queryKey: ["events", filter],
    queryFn: () => getEvents(filter),
  })
}
