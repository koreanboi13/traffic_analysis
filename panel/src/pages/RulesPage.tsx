import { useMemo, useState } from "react"
import { useQueryClient } from "@tanstack/react-query"
import { Loader2, Pencil, Plus, Trash2 } from "lucide-react"
import { toast } from "sonner"

import { Header } from "@/components/layout/Header"
import { EmptyState } from "@/components/common/EmptyState"
import { ErrorState } from "@/components/common/ErrorState"
import { LogOnlyToggle } from "@/components/common/LogOnlyToggle"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Slider } from "@/components/ui/slider"
import { Switch } from "@/components/ui/switch"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { useRules, useCreateRule, useDeleteRule, useUpdateRule } from "@/hooks/useRules"
import { useAuthStore } from "@/store/authStore"
import type { Rule, RuleCategory, RuleRequest, RuleType } from "@/types"

type FilterType = "all" | RuleType
type FilterCategory = "all" | RuleCategory

type RuleFormErrors = Partial<Record<"ruleId" | "name" | "type" | "category" | "pattern" | "targets" | "weight", string>>

interface RuleFormState {
  ruleId: string
  name: string
  type: RuleType
  category: RuleCategory
  pattern: string
  targets: string[]
  weight: number
  enabled: boolean
  logOnly: boolean
}

const TARGET_OPTIONS = ["query", "headers", "cookies", "body"] as const

function getDefaultForm(): RuleFormState {
  return {
    ruleId: "",
    name: "",
    type: "regex",
    category: "sqli",
    pattern: "",
    targets: ["query"],
    weight: 5,
    enabled: true,
    logOnly: false,
  }
}

function toForm(rule: Rule): RuleFormState {
  return {
    ruleId: rule.ID,
    name: rule.Name,
    type: rule.Type,
    category: rule.Category,
    pattern: rule.Type === "regex" ? rule.Pattern : rule.Heuristic,
    targets: rule.Targets.length > 0 ? rule.Targets : ["query"],
    weight: Math.round(rule.Weight),
    enabled: rule.Enabled,
    logOnly: rule.LogOnly,
  }
}

function validateForm(form: RuleFormState, isCreate: boolean): RuleFormErrors {
  const errors: RuleFormErrors = {}

  if (isCreate && form.ruleId.trim().length === 0) {
    errors.ruleId = "Rule ID is required"
  }
  if (form.name.trim().length === 0) {
    errors.name = "Name is required"
  } else if (form.name.trim().length > 100) {
    errors.name = "Name must be at most 100 characters"
  }
  if (!form.type) {
    errors.type = "Type is required"
  }
  if (!form.category) {
    errors.category = "Category is required"
  }
  if (form.type === "regex" && form.pattern.trim().length === 0) {
    errors.pattern = "Pattern is required for regex rules"
  }
  if (form.targets.length === 0) {
    errors.targets = "Select at least one target"
  }
  if (!Number.isFinite(form.weight) || form.weight < 1 || form.weight > 10) {
    errors.weight = "Weight must be between 1 and 10"
  }

  return errors
}

function buildRuleRequest(form: RuleFormState, mode: "create" | "edit"): RuleRequest {
  const payload: RuleRequest = {
    name: form.name.trim(),
    type: form.type,
    category: form.category,
    targets: form.targets,
    weight: form.weight,
    enabled: form.enabled,
    log_only: form.enabled ? form.logOnly : false,
  }

  if (mode === "create") {
    payload.rule_id = form.ruleId.trim()
  }

  if (form.type === "regex") {
    payload.pattern = form.pattern.trim()
  } else {
    payload.heuristic = form.pattern.trim()
  }

  return payload
}

function getCategoryBadge(category: RuleCategory) {
  if (category === "sqli") {
    return (
      <Badge variant="destructive" className="bg-red-700/20 text-red-300">
        sqli
      </Badge>
    )
  }

  return <Badge variant="secondary">xss</Badge>
}

export function RulesPage() {
  const queryClient = useQueryClient()
  const role = useAuthStore((state) => state.role)
  const isAdmin = role === "admin"

  const [typeFilter, setTypeFilter] = useState<FilterType>("all")
  const [categoryFilter, setCategoryFilter] = useState<FilterCategory>("all")

  const [dialogOpen, setDialogOpen] = useState(false)
  const [dialogMode, setDialogMode] = useState<"create" | "edit">("create")
  const [editingRule, setEditingRule] = useState<Rule | null>(null)
  const [form, setForm] = useState<RuleFormState>(getDefaultForm)
  const [errors, setErrors] = useState<RuleFormErrors>({})
  const [submitError, setSubmitError] = useState<string | null>(null)

  const [deleteTarget, setDeleteTarget] = useState<Rule | null>(null)
  const [pendingToggleIds, setPendingToggleIds] = useState<Set<string>>(new Set())

  const rulesQuery = useRules()
  const createRuleMutation = useCreateRule()
  const updateRuleMutation = useUpdateRule()
  const deleteRuleMutation = useDeleteRule()

  const rules = rulesQuery.data ?? []
  const filteredRules = useMemo(() => {
    return rules.filter((rule) => {
      const passType = typeFilter === "all" || rule.Type === typeFilter
      const passCategory = categoryFilter === "all" || rule.Category === categoryFilter
      return passType && passCategory
    })
  }, [categoryFilter, rules, typeFilter])

  const openCreateDialog = () => {
    setDialogMode("create")
    setEditingRule(null)
    setForm(getDefaultForm())
    setErrors({})
    setSubmitError(null)
    setDialogOpen(true)
  }

  const openEditDialog = (rule: Rule) => {
    setDialogMode("edit")
    setEditingRule(rule)
    setForm(toForm(rule))
    setErrors({})
    setSubmitError(null)
    setDialogOpen(true)
  }

  const toggleTarget = (target: string, checked: boolean) => {
    setForm((prev) => {
      const nextTargets = checked
        ? Array.from(new Set([...prev.targets, target]))
        : prev.targets.filter((item) => item !== target)
      return { ...prev, targets: nextTargets }
    })
  }

  const saveRule = async () => {
    const nextErrors = validateForm(form, dialogMode === "create")
    setErrors(nextErrors)
    setSubmitError(null)

    if (Object.keys(nextErrors).length > 0) {
      return
    }

    try {
      const payload = buildRuleRequest(form, dialogMode)
      if (dialogMode === "create") {
        await createRuleMutation.mutateAsync(payload)
        toast.success("Rule created")
      } else if (editingRule) {
        await updateRuleMutation.mutateAsync({ id: editingRule.ID, data: payload })
        toast.success("Rule updated")
      }

      setDialogOpen(false)
    } catch {
      setSubmitError("Failed to save rule. Please review fields and try again.")
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget) {
      return
    }

    try {
      await deleteRuleMutation.mutateAsync(deleteTarget.ID)
      toast.success("Rule deleted")
      setDeleteTarget(null)
    } catch {
      toast.error("Failed to delete rule. Try again.")
    }
  }

  const handleStatusToggle = async (rule: Rule, enabled: boolean, logOnly: boolean) => {
    if (!isAdmin) {
      return
    }

    const previous = queryClient.getQueryData<Rule[]>(["rules"]) ?? []
    setPendingToggleIds((prev) => new Set(prev).add(rule.ID))

    queryClient.setQueryData<Rule[]>(["rules"], (current) => {
      if (!current) {
        return current
      }

      return current.map((item) =>
        item.ID === rule.ID ? { ...item, Enabled: enabled, LogOnly: enabled ? logOnly : false } : item,
      )
    })

    try {
      await updateRuleMutation.mutateAsync({
        id: rule.ID,
        data: {
          name: rule.Name,
          type: rule.Type,
          category: rule.Category,
          pattern: rule.Pattern,
          heuristic: rule.Heuristic,
          threshold: rule.Threshold,
          targets: rule.Targets,
          weight: rule.Weight,
          enabled,
          log_only: enabled ? logOnly : false,
        },
      })
    } catch {
      queryClient.setQueryData(["rules"], previous)
      toast.error("Failed to update rule status")
    } finally {
      setPendingToggleIds((prev) => {
        const next = new Set(prev)
        next.delete(rule.ID)
        return next
      })
    }
  }

  const isSaving = createRuleMutation.isPending || updateRuleMutation.isPending

  return (
    <section>
      <Header
        title="Rules"
        actions={
          isAdmin ? (
            <Button className="bg-blue-600 text-white hover:bg-blue-500" onClick={openCreateDialog}>
              <Plus className="size-4" />
              Create Rule
            </Button>
          ) : undefined
        }
      />

      <div className="space-y-6 px-8 py-6">
        <div className="flex flex-wrap gap-3">
          <div className="min-w-40 space-y-2">
            <label className="text-xs text-zinc-400">Type</label>
            <Select value={typeFilter} onValueChange={(value) => setTypeFilter(value as FilterType)}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All types</SelectItem>
                <SelectItem value="regex">regex</SelectItem>
                <SelectItem value="heuristic">heuristic</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="min-w-40 space-y-2">
            <label className="text-xs text-zinc-400">Category</label>
            <Select value={categoryFilter} onValueChange={(value) => setCategoryFilter(value as FilterCategory)}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All categories</SelectItem>
                <SelectItem value="sqli">sqli</SelectItem>
                <SelectItem value="xss">xss</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>

        {rulesQuery.isLoading ? (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((_, index) => (
                <Skeleton key={index} className="h-10 w-full bg-zinc-800" />
              ))}
            </div>
          </div>
        ) : null}

        {!rulesQuery.isLoading && rulesQuery.isError ? (
          <ErrorState
            message="Could not connect to WAF API"
            detail="Check that the proxy service is running on port 8090."
            onRetry={() => {
              void rulesQuery.refetch()
            }}
          />
        ) : null}

        {!rulesQuery.isLoading && !rulesQuery.isError && filteredRules.length === 0 ? (
          <EmptyState
            heading="No rules configured"
            body={
              isAdmin
                ? "Create your first detection rule to start blocking threats."
                : "No rules are configured yet."
            }
          />
        ) : null}

        {!rulesQuery.isLoading && !rulesQuery.isError && filteredRules.length > 0 ? (
          <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900">
            <Table>
              <TableHeader>
                <TableRow className="border-zinc-800 hover:bg-transparent">
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead className="text-right">Weight</TableHead>
                  <TableHead>Status</TableHead>
                  {isAdmin ? <TableHead>Actions</TableHead> : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredRules.map((rule) => (
                  <TableRow key={rule.ID} className="border-zinc-800 hover:bg-zinc-800/50">
                    <TableCell>
                      {isAdmin ? (
                        <button
                          type="button"
                          className="text-left text-zinc-100 hover:text-blue-400"
                          onClick={() => openEditDialog(rule)}
                        >
                          {rule.Name}
                        </button>
                      ) : (
                        <span className="text-zinc-100">{rule.Name}</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{rule.Type}</Badge>
                    </TableCell>
                    <TableCell>{getCategoryBadge(rule.Category)}</TableCell>
                    <TableCell className="text-right">{Math.round(rule.Weight)} / 10</TableCell>
                    <TableCell>
                      <LogOnlyToggle
                        enabled={rule.Enabled}
                        logOnly={rule.LogOnly}
                        disabled={!isAdmin || pendingToggleIds.has(rule.ID)}
                        onToggle={(enabled, logOnly) => {
                          void handleStatusToggle(rule, enabled, logOnly)
                        }}
                      />
                    </TableCell>
                    {isAdmin ? (
                      <TableCell>
                        <div className="flex gap-2">
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            onClick={() => openEditDialog(rule)}
                            aria-label={`Edit ${rule.Name}`}
                          >
                            <Pencil className="size-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            onClick={() => setDeleteTarget(rule)}
                            aria-label={`Delete ${rule.Name}`}
                          >
                            <Trash2 className="size-4 text-red-400" />
                          </Button>
                        </div>
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : null}
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-2xl bg-zinc-900 text-zinc-100" showCloseButton>
          <DialogHeader>
            <DialogTitle>{dialogMode === "create" ? "Create Rule" : "Edit Rule"}</DialogTitle>
            <DialogDescription>
              Configure detection settings and target areas for this rule.
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-2 md:grid-cols-2">
            {dialogMode === "create" ? (
              <div className="space-y-2 md:col-span-2">
                <label className="text-xs text-zinc-400" htmlFor="rule-id">
                  Rule ID
                </label>
                <Input
                  id="rule-id"
                  value={form.ruleId}
                  onChange={(event) => setForm((prev) => ({ ...prev, ruleId: event.target.value }))}
                />
                {errors.ruleId ? <p className="text-xs text-red-400">{errors.ruleId}</p> : null}
              </div>
            ) : null}

            <div className="space-y-2 md:col-span-2">
              <label className="text-xs text-zinc-400" htmlFor="rule-name">
                Name
              </label>
              <Input
                id="rule-name"
                value={form.name}
                onChange={(event) => setForm((prev) => ({ ...prev, name: event.target.value }))}
              />
              {errors.name ? <p className="text-xs text-red-400">{errors.name}</p> : null}
            </div>

            <div className="space-y-2">
              <label className="text-xs text-zinc-400">Type</label>
              <Select value={form.type} onValueChange={(value) => setForm((prev) => ({ ...prev, type: value as RuleType }))}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="regex">regex</SelectItem>
                  <SelectItem value="heuristic">heuristic</SelectItem>
                </SelectContent>
              </Select>
              {errors.type ? <p className="text-xs text-red-400">{errors.type}</p> : null}
            </div>

            <div className="space-y-2">
              <label className="text-xs text-zinc-400">Category</label>
              <Select
                value={form.category}
                onValueChange={(value) => setForm((prev) => ({ ...prev, category: value as RuleCategory }))}
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="sqli">sqli</SelectItem>
                  <SelectItem value="xss">xss</SelectItem>
                </SelectContent>
              </Select>
              {errors.category ? <p className="text-xs text-red-400">{errors.category}</p> : null}
            </div>

            <div className="space-y-2 md:col-span-2">
              <label className="text-xs text-zinc-400" htmlFor="rule-pattern">
                Pattern
              </label>
              <Textarea
                id="rule-pattern"
                rows={4}
                className="font-mono"
                value={form.pattern}
                onChange={(event) => setForm((prev) => ({ ...prev, pattern: event.target.value }))}
              />
              {errors.pattern ? <p className="text-xs text-red-400">{errors.pattern}</p> : null}
            </div>

            <div className="space-y-2 md:col-span-2">
              <label className="text-xs text-zinc-400">Targets</label>
              <div className="grid gap-2 sm:grid-cols-2">
                {TARGET_OPTIONS.map((target) => (
                  <label key={target} className="flex items-center gap-2 text-sm text-zinc-200">
                    <Checkbox
                      checked={form.targets.includes(target)}
                      onCheckedChange={(checked) => toggleTarget(target, Boolean(checked))}
                    />
                    <span>{target}</span>
                  </label>
                ))}
              </div>
              {errors.targets ? <p className="text-xs text-red-400">{errors.targets}</p> : null}
            </div>

            <div className="space-y-2 md:col-span-2">
              <label className="text-xs text-zinc-400">Weight</label>
              <div className="flex items-center gap-3">
                <Slider
                  min={1}
                  max={10}
                  step={1}
                  value={[form.weight]}
                  onValueChange={(value) => {
                    const nextWeight = Array.isArray(value) ? value[0] : value
                    setForm((prev) => ({ ...prev, weight: nextWeight ?? prev.weight }))
                  }}
                />
                <span className="w-10 text-right text-sm">{form.weight}</span>
              </div>
              {errors.weight ? <p className="text-xs text-red-400">{errors.weight}</p> : null}
            </div>

            <div className="flex items-center gap-2 md:col-span-2">
              <Switch
                checked={form.enabled}
                onCheckedChange={(checked) =>
                  setForm((prev) => ({ ...prev, enabled: checked, logOnly: checked ? prev.logOnly : false }))
                }
              />
              <span className="text-sm text-zinc-200">Enabled</span>
            </div>

            {submitError ? <p className="text-sm text-red-400 md:col-span-2">{submitError}</p> : null}
          </div>

          <DialogFooter className="bg-zinc-900">
            <Button variant="outline" onClick={() => setDialogOpen(false)} disabled={isSaving}>
              {dialogMode === "create" ? "Discard" : "Discard Changes"}
            </Button>
            <Button className="bg-blue-600 text-white hover:bg-blue-500" onClick={() => void saveRule()} disabled={isSaving}>
              {isSaving ? <Loader2 className="size-4 animate-spin" /> : null}
              {dialogMode === "create" ? "Save Rule" : "Save Changes"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={Boolean(deleteTarget)} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent className="bg-zinc-900 text-zinc-100">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete rule?</AlertDialogTitle>
            <AlertDialogDescription>
              Rule <strong>{deleteTarget?.Name}</strong> will be permanently deleted. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel variant="outline">Keep Rule</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => void handleDelete()}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  )
}
