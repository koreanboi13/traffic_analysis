import { MemoryRouter } from "react-router-dom"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { EventDetailPage } from "@/pages/EventDetailPage"
import { EventsPage } from "@/pages/EventsPage"
import type { Event, EventFilter, PaginatedEvents } from "@/types"

const mockNavigate = vi.fn()
const mockSetFilter = vi.fn()
const mockResetFilter = vi.fn()
const mockUseEvents = vi.fn()

const storeState: {
  filter: EventFilter
  setFilter: (patch: Partial<EventFilter>) => void
  resetFilter: () => void
} = {
  filter: { limit: 20, offset: 0 },
  setFilter: (patch) => mockSetFilter(patch),
  resetFilter: () => mockResetFilter(),
}

vi.mock("@/hooks/useEvents", () => ({
  useEvents: (filter: EventFilter) => mockUseEvents(filter),
}))

vi.mock("@/store/filterStore", () => ({
  useFilterStore: <T,>(selector: (state: typeof storeState) => T): T => selector(storeState),
}))

vi.mock("react-router-dom", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-router-dom")>()
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

const eventFixture: Event = {
  EventID: "evt-1",
  Timestamp: 1712600000000,
  RequestID: "req-1",
  ClientIP: "192.168.1.10",
  Host: "example.local",
  Method: "GET",
  Path: "/api/v1/users?id=1",
  NormalizedPath: "/api/v1/users",
  Verdict: "block",
  StatusCode: 403,
  LatencyMs: 12.5,
  RawQuery: "id=1",
  NormalizedQuery: "id=?",
  RawBody: "{\"name\":\"john\"}",
  NormalizedBody: "{\"name\":\"?\"}",
  QueryParams: "{\"id\":\"1\"}",
  BodyParams: "{\"name\":\"john\"}",
  Headers: "{\"user-agent\":\"vitest\"}",
  Cookies: "{\"session\":\"abc\"}",
  UserAgent: "vitest",
  ContentType: "application/json",
  Referer: "https://example.local",
  BodyTruncated: 1,
  BodySize: 123,
  RuleIDs: ["rule-1", "rule-2"],
  Score: 9.5,
}

function makeEventsResult(total = 40): {
  data: PaginatedEvents
  isLoading: boolean
  isError: boolean
  refetch: ReturnType<typeof vi.fn>
  isFetching: boolean
} {
  return {
    data: {
      data: [eventFixture],
      total,
      offset: storeState.filter.offset ?? 0,
      limit: 20,
    },
    isLoading: false,
    isError: false,
    refetch: vi.fn(),
    isFetching: false,
  }
}

describe("events pages", () => {
  beforeEach(() => {
    mockNavigate.mockReset()
    mockSetFilter.mockReset()
    mockResetFilter.mockReset()
    storeState.filter = { limit: 20, offset: 0 }
    mockUseEvents.mockReturnValue(makeEventsResult())
  })

  it("filters apply and reset update state", async () => {
    const user = userEvent.setup()

    render(
      <MemoryRouter>
        <EventsPage />
      </MemoryRouter>,
    )

    const dateInputs = Array.from(document.querySelectorAll('input[type="datetime-local"]')) as HTMLInputElement[]
    expect(dateInputs.length).toBe(2)

    await user.type(dateInputs[0], "2026-04-09T10:30")
    await user.type(dateInputs[1], "2026-04-09T11:30")
    await user.type(screen.getByPlaceholderText("e.g. 192.168.1.1"), "192.168.1.1")
    await user.type(screen.getByPlaceholderText("Rule ID"), "rule-1")

    await user.click(screen.getByRole("button", { name: "Apply Filters" }))

    expect(mockSetFilter).toHaveBeenCalledWith(
      expect.objectContaining({
        ip: "192.168.1.1",
        rule_id: "rule-1",
        limit: 20,
        offset: 0,
      }),
    )

    await user.click(screen.getByRole("button", { name: "Reset Filters" }))

    expect(mockResetFilter).toHaveBeenCalledTimes(1)
    expect((screen.getByPlaceholderText("e.g. 192.168.1.1") as HTMLInputElement).value).toBe("")
    expect((screen.getByPlaceholderText("Rule ID") as HTMLInputElement).value).toBe("")
  })

  it("table renders all seven columns", () => {
    render(
      <MemoryRouter>
        <EventsPage />
      </MemoryRouter>,
    )

    expect(screen.getByRole("columnheader", { name: "Timestamp" })).toBeInTheDocument()
    expect(screen.getByRole("columnheader", { name: "IP" })).toBeInTheDocument()
    expect(screen.getByRole("columnheader", { name: "Method" })).toBeInTheDocument()
    expect(screen.getByRole("columnheader", { name: "Path" })).toBeInTheDocument()
    expect(screen.getByRole("columnheader", { name: "Verdict" })).toBeInTheDocument()
    expect(screen.getByRole("columnheader", { name: "Score" })).toBeInTheDocument()
    expect(screen.getByRole("columnheader", { name: "Actions" })).toBeInTheDocument()
  })

  it("pagination switches pages with prev and next", async () => {
    const user = userEvent.setup()

    render(
      <MemoryRouter>
        <EventsPage />
      </MemoryRouter>,
    )

    expect(screen.getByText("Page 1 of 2")).toBeInTheDocument()
    await user.click(screen.getByRole("button", { name: "Next" }))
    expect(mockSetFilter).toHaveBeenCalledWith({ offset: 20, limit: 20 })

    mockSetFilter.mockReset()
    storeState.filter = { limit: 20, offset: 20 }
    mockUseEvents.mockReturnValue(makeEventsResult())

    render(
      <MemoryRouter>
        <EventsPage />
      </MemoryRouter>,
    )

    expect(screen.getAllByText("Page 2 of 2").length).toBeGreaterThan(0)
    await user.click(screen.getAllByRole("button", { name: "Prev" })[1])
    expect(mockSetFilter).toHaveBeenCalledWith({ offset: 0, limit: 20 })
  })

  it("event detail shows metadata, tabs and matched rules", async () => {
    const user = userEvent.setup()

    render(
      <MemoryRouter initialEntries={[{ pathname: "/events/evt-1", state: { event: eventFixture } }]}>
        <EventDetailPage />
      </MemoryRouter>,
    )

    expect(screen.getByText("Request metadata")).toBeInTheDocument()
    expect(screen.getByText("example.local")).toBeInTheDocument()
    expect(screen.getByText(/Score:/)).toBeInTheDocument()
    expect(screen.getByText("Request body was truncated for analysis (limit exceeded).")).toBeInTheDocument()

    await user.click(screen.getByRole("tab", { name: "Normalized" }))
    expect(screen.getByText(/NormalizedPath:/)).toBeInTheDocument()

    expect(screen.getByText("rule-1")).toBeInTheDocument()
    expect(screen.getByText("rule-2")).toBeInTheDocument()
  })
})
