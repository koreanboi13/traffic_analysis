import { apiClient } from "@/api/client"
import type { Rule, RuleRequest } from "@/types"

export async function getRules(): Promise<Rule[]> {
  const response = await apiClient.get<Rule[]>("/api/rules")
  return response.data
}

export async function getRule(id: string): Promise<Rule> {
  const response = await apiClient.get<Rule>(`/api/rules/${id}`)
  return response.data
}

export async function createRule(data: RuleRequest): Promise<Rule> {
  const response = await apiClient.post<Rule>("/api/rules", data)
  return response.data
}

export async function updateRule(id: string, data: RuleRequest): Promise<Rule> {
  const response = await apiClient.put<Rule>(`/api/rules/${id}`, data)
  return response.data
}

export async function deleteRule(id: string): Promise<void> {
  await apiClient.delete(`/api/rules/${id}`)
}
