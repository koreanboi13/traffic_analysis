import { apiClient } from "./client"
import type { User, CreateUserRequest } from "@/types"

export async function getUsers(): Promise<User[]> {
  const { data } = await apiClient.get<User[]>("/api/users")
  return data
}

export async function createUser(req: CreateUserRequest): Promise<User> {
  const { data } = await apiClient.post<User>("/api/users", req)
  return data
}

export async function deleteUser(id: number): Promise<void> {
  await apiClient.delete(`/api/users/${id}`)
}
