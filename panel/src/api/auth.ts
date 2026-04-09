import { apiClient } from "@/api/client"
import type { LoginRequest, LoginResponse } from "@/types"

export async function login(data: LoginRequest): Promise<LoginResponse> {
  const response = await apiClient.post<LoginResponse>("/api/auth/login", data)
  return response.data
}
