import { create } from "zustand"
import type { EventFilter } from "@/types"

interface FilterStore {
  filter: EventFilter
  setFilter: (patch: Partial<EventFilter>) => void
  resetFilter: () => void
}

const DEFAULT_FILTER: EventFilter = {
  limit: 20,
  offset: 0,
}

function hasNonOffsetChanges(current: EventFilter, patch: Partial<EventFilter>): boolean {
  const entries = Object.entries(patch).filter(([key]) => key !== "offset")
  return entries.some(([key, value]) => current[key as keyof EventFilter] !== value)
}

export const useFilterStore = create<FilterStore>((set) => ({
  filter: DEFAULT_FILTER,
  setFilter: (patch) =>
    set((state) => {
      const next = { ...state.filter, ...patch }

      if (hasNonOffsetChanges(state.filter, patch)) {
        next.offset = 0
      }

      return { filter: next }
    }),
  resetFilter: () => set({ filter: DEFAULT_FILTER }),
}))
