import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { createRule, deleteRule, getRules, updateRule } from "@/api/rules"
import type { RuleRequest } from "@/types"

export function useRules() {
  return useQuery({
    queryKey: ["rules"],
    queryFn: getRules,
  })
}

export function useCreateRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (data: RuleRequest) => createRule(data),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rules"] })
    },
  })
}

export function useUpdateRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: RuleRequest }) => updateRule(id, data),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rules"] })
    },
  })
}

export function useDeleteRule() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => deleteRule(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["rules"] })
    },
  })
}
