import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { describe, expect, it, vi } from "vitest"

import { DashboardPage } from "@/pages/DashboardPage"
import type { DashboardPreset } from "@/hooks/useDashboard"

const mockRefetch = vi.fn()
const mockUseDashboard = vi.fn()

vi.mock("@/hooks/useDashboard", () => ({
  useDashboard: (preset: DashboardPreset) => mockUseDashboard(preset),
}))

describe("DashboardPage", () => {
  it("renders four KPI cards and three charts sections", () => {
    mockUseDashboard.mockReturnValue({
      data: {
        totalRequests: 120,
        blocked: 15,
        blockRate: "12.5",
        logOnly: 8,
        timeSeries: [{ label: "12:00", blocked: 3, timestamp: Date.now() }],
        topRules: [{ name: "rule-1", count: 4 }],
        topPaths: [{ name: "/login", count: 2 }],
      },
      isLoading: false,
      isError: false,
      isFetching: false,
      refetch: mockRefetch,
    })

    render(<DashboardPage />)

    expect(screen.getByText("Total Requests")).toBeInTheDocument()
    expect(screen.getByText("Blocked")).toBeInTheDocument()
    expect(screen.getByText("Block Rate")).toBeInTheDocument()
    expect(screen.getByText("Alerts (Log Only)")).toBeInTheDocument()

    expect(screen.getByText("Block Rate Over Time")).toBeInTheDocument()
    expect(screen.getByText("Top 5 Rules")).toBeInTheDocument()
    expect(screen.getByText("Top 5 Paths")).toBeInTheDocument()
  })

  it("switches presets and triggers refresh", async () => {
    mockUseDashboard.mockImplementation((preset: DashboardPreset) => ({
      data: {
        totalRequests: 0,
        blocked: 0,
        blockRate: "0.0",
        logOnly: 0,
        timeSeries: [],
        topRules: [],
        topPaths: [],
      },
      isLoading: false,
      isError: false,
      isFetching: false,
      refetch: mockRefetch,
      presetObserved: preset,
    }))

    const user = userEvent.setup()
    render(<DashboardPage />)

    await user.click(screen.getByRole("button", { name: "7d" }))
    expect(mockUseDashboard).toHaveBeenLastCalledWith("7d")

    await user.click(screen.getByRole("button", { name: "Refresh data" }))
    expect(mockRefetch).toHaveBeenCalledTimes(1)
  })
})
