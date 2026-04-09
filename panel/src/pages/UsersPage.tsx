import { useState } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Loader2, Plus, Trash2, Users } from "lucide-react"
import { toast } from "sonner"

import { Header } from "@/components/layout/Header"
import { EmptyState } from "@/components/common/EmptyState"
import { ErrorState } from "@/components/common/ErrorState"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { getUsers, createUser, deleteUser } from "@/api/users"
import { useAuthStore } from "@/store/authStore"
import type { User, UserRole } from "@/types"

interface CreateFormState {
  username: string
  password: string
  role: UserRole
}

interface CreateFormErrors {
  username?: string
  password?: string
}

function getDefaultForm(): CreateFormState {
  return { username: "", password: "", role: "analyst" }
}

function validateForm(form: CreateFormState): CreateFormErrors {
  const errors: CreateFormErrors = {}
  if (form.username.trim().length === 0) {
    errors.username = "Username is required"
  } else if (form.username.trim().length < 3) {
    errors.username = "Username must be at least 3 characters"
  }
  if (form.password.length === 0) {
    errors.password = "Password is required"
  } else if (form.password.length < 6) {
    errors.password = "Password must be at least 6 characters"
  }
  return errors
}

function getRoleBadge(role: UserRole) {
  if (role === "admin") {
    return (
      <Badge variant="destructive" className="bg-red-700/20 text-red-300">
        admin
      </Badge>
    )
  }
  return <Badge variant="secondary">analyst</Badge>
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

export function UsersPage() {
  const queryClient = useQueryClient()
  const currentUsername = useAuthStore((state) => state.username)

  const [dialogOpen, setDialogOpen] = useState(false)
  const [form, setForm] = useState<CreateFormState>(getDefaultForm)
  const [errors, setErrors] = useState<CreateFormErrors>({})
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<User | null>(null)

  const usersQuery = useQuery({
    queryKey: ["users"],
    queryFn: getUsers,
  })

  const createMutation = useMutation({
    mutationFn: createUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] })
    },
  })

  const users = usersQuery.data ?? []

  const openCreateDialog = () => {
    setForm(getDefaultForm())
    setErrors({})
    setSubmitError(null)
    setDialogOpen(true)
  }

  const handleCreate = async () => {
    const nextErrors = validateForm(form)
    setErrors(nextErrors)
    setSubmitError(null)

    if (Object.keys(nextErrors).length > 0) {
      return
    }

    try {
      await createMutation.mutateAsync({
        username: form.username.trim(),
        password: form.password,
        role: form.role,
      })
      toast.success("User created")
      setDialogOpen(false)
    } catch (err) {
      const message =
        (err as { response?: { status?: number } })?.response?.status === 409
          ? "User with this username already exists"
          : "Failed to create user. Please try again."
      setSubmitError(message)
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return

    try {
      await deleteMutation.mutateAsync(deleteTarget.id)
      toast.success("User deleted")
      setDeleteTarget(null)
    } catch {
      toast.error("Failed to delete user")
    }
  }

  return (
    <section>
      <Header
        title="Users"
        actions={
          <Button className="bg-blue-600 text-white hover:bg-blue-500" onClick={openCreateDialog}>
            <Plus className="size-4" />
            Create User
          </Button>
        }
      />

      <div className="space-y-6 px-8 py-6">
        {usersQuery.isLoading ? (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <div className="space-y-3">
              {Array.from({ length: 4 }).map((_, index) => (
                <Skeleton key={index} className="h-10 w-full bg-zinc-800" />
              ))}
            </div>
          </div>
        ) : null}

        {!usersQuery.isLoading && usersQuery.isError ? (
          <ErrorState
            message="Could not load users"
            detail="Check that the WAF API is running on port 8090."
            onRetry={() => {
              void usersQuery.refetch()
            }}
          />
        ) : null}

        {!usersQuery.isLoading && !usersQuery.isError && users.length === 0 ? (
          <EmptyState
            heading="No users found"
            body="Create your first user to get started."
          />
        ) : null}

        {!usersQuery.isLoading && !usersQuery.isError && users.length > 0 ? (
          <div className="overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-zinc-800 hover:bg-transparent">
                    <TableHead>Username</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {users.map((user) => (
                    <TableRow key={user.id} className="border-zinc-800 hover:bg-zinc-800/50">
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Users className="size-4 text-zinc-500" />
                          <span className="text-zinc-100">{user.username}</span>
                          {user.username === currentUsername ? (
                            <Badge variant="outline" className="text-xs">
                              you
                            </Badge>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell>{getRoleBadge(user.role)}</TableCell>
                      <TableCell className="text-zinc-400">
                        {formatDate(user.created_at)}
                      </TableCell>
                      <TableCell>
                        {user.username === currentUsername ? (
                          <span className="text-xs text-zinc-600">—</span>
                        ) : (
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            onClick={() => setDeleteTarget(user)}
                            aria-label={`Delete ${user.username}`}
                          >
                            <Trash2 className="size-4 text-red-400" />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </div>
        ) : null}
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-w-md bg-zinc-900 text-zinc-100" showCloseButton>
          <DialogHeader>
            <DialogTitle>Create User</DialogTitle>
            <DialogDescription>
              Add a new user to the WAF admin panel.
            </DialogDescription>
          </DialogHeader>

          <div className="grid gap-4 py-2">
            <div className="space-y-2">
              <label className="text-xs text-zinc-400" htmlFor="new-username">
                Username
              </label>
              <Input
                id="new-username"
                autoComplete="off"
                value={form.username}
                onChange={(e) => setForm((prev) => ({ ...prev, username: e.target.value }))}
              />
              {errors.username ? <p className="text-xs text-red-400">{errors.username}</p> : null}
            </div>

            <div className="space-y-2">
              <label className="text-xs text-zinc-400" htmlFor="new-password">
                Password
              </label>
              <Input
                id="new-password"
                type="password"
                autoComplete="new-password"
                value={form.password}
                onChange={(e) => setForm((prev) => ({ ...prev, password: e.target.value }))}
              />
              {errors.password ? <p className="text-xs text-red-400">{errors.password}</p> : null}
            </div>

            <div className="space-y-2">
              <label className="text-xs text-zinc-400">Role</label>
              <Select
                value={form.role}
                onValueChange={(value) => setForm((prev) => ({ ...prev, role: value as UserRole }))}
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="analyst">analyst</SelectItem>
                  <SelectItem value="admin">admin</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {submitError ? <p className="text-sm text-red-400">{submitError}</p> : null}
          </div>

          <DialogFooter className="bg-zinc-900">
            <Button
              variant="outline"
              onClick={() => setDialogOpen(false)}
              disabled={createMutation.isPending}
            >
              Cancel
            </Button>
            <Button
              className="bg-blue-600 text-white hover:bg-blue-500"
              onClick={() => void handleCreate()}
              disabled={createMutation.isPending}
            >
              {createMutation.isPending ? <Loader2 className="size-4 animate-spin" /> : null}
              Create User
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog open={Boolean(deleteTarget)} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent className="bg-zinc-900 text-zinc-100">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete user?</AlertDialogTitle>
            <AlertDialogDescription>
              User <strong>{deleteTarget?.username}</strong> will be permanently deleted. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel variant="outline">Cancel</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => void handleDelete()}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  )
}
