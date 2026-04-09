import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

import { RulesPage } from "@/pages/RulesPage"
import type { Rule, UserRole } from "@/types"

const mockCreateRule = vi.fn()
const mockUpdateRule = vi.fn()
const mockDeleteRule = vi.fn()
const mockRefetch = vi.fn()

let currentRole: UserRole = "admin"

const rulesFixture: Rule[] = [
  {
    ID: "rule-1",
    Name: "Detect SQL UNION",
    Type: "regex",
    Category: "sqli",
    Pattern: "union\\s+select",
    Heuristic: "",
    Threshold: 0,
    Targets: ["query", "body"],
    Weight: 7,
    Enabled: true,
    LogOnly: false,
  },
]

vi.mock("@/store/authStore", () => ({
  useAuthStore: <T,>(selector: (state: { role: UserRole }) => T): T => selector({ role: currentRole }),
}))

vi.mock("@/hooks/useRules", () => ({
  useRules: () => ({
    data: rulesFixture,
    isLoading: false,
    isError: false,
    refetch: mockRefetch,
  }),
  useCreateRule: () => ({
    mutateAsync: mockCreateRule,
    isPending: false,
  }),
  useUpdateRule: () => ({
    mutateAsync: mockUpdateRule,
    isPending: false,
  }),
  useDeleteRule: () => ({
    mutateAsync: mockDeleteRule,
    isPending: false,
  }),
}))

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })

  return render(
    <QueryClientProvider client={queryClient}>
      <RulesPage />
    </QueryClientProvider>,
  )
}

describe("RulesPage", () => {
  beforeEach(() => {
    currentRole = "admin"
    mockCreateRule.mockReset().mockResolvedValue(rulesFixture[0])
    mockUpdateRule.mockReset().mockResolvedValue(rulesFixture[0])
    mockDeleteRule.mockReset().mockResolvedValue(undefined)
    mockRefetch.mockReset()
  })

  it("shows admin actions and hides them for analyst", () => {
    const adminView = renderPage()

    expect(screen.getByRole("button", { name: "Create Rule" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Edit Detect SQL UNION" })).toBeInTheDocument()

    adminView.unmount()
    currentRole = "analyst"
    renderPage()

    expect(screen.queryByRole("button", { name: "Create Rule" })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Edit Detect SQL UNION" })).not.toBeInTheDocument()
  })

  it("cycles status toggle and calls update API", async () => {
    const user = userEvent.setup()
    renderPage()

    await user.click(screen.getByRole("button", { name: "Enabled" }))

    expect(mockUpdateRule).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "rule-1",
        data: expect.objectContaining({
          enabled: true,
          log_only: true,
        }),
      }),
    )
  })

  it("supports create, edit and delete flows", async () => {
    const user = userEvent.setup()
    renderPage()

    await user.click(screen.getByRole("button", { name: "Create Rule" }))
    await user.type(screen.getByLabelText("Rule ID"), "rule-new")
    await user.type(screen.getByLabelText("Name"), "Block XSS payload")
    await user.type(screen.getByLabelText("Pattern"), "<script")
    await user.click(screen.getByRole("button", { name: "Save Rule" }))

    expect(mockCreateRule).toHaveBeenCalledWith(
      expect.objectContaining({
        rule_id: "rule-new",
        name: "Block XSS payload",
        type: "regex",
      }),
    )

    await user.click(screen.getByRole("button", { name: "Edit Detect SQL UNION" }))
    const editName = screen.getByLabelText("Name")
    await user.clear(editName)
    await user.type(editName, "Detect UNION (updated)")
    await user.click(screen.getByRole("button", { name: "Save Changes" }))

    expect(mockUpdateRule).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "rule-1",
        data: expect.objectContaining({
          name: "Detect UNION (updated)",
        }),
      }),
    )

    await user.click(screen.getByRole("button", { name: "Delete Detect SQL UNION" }))
    await user.click(screen.getByRole("button", { name: "Delete" }))

    expect(mockDeleteRule).toHaveBeenCalledWith("rule-1")
  })
})
