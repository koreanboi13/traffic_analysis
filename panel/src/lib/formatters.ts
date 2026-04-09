import { format } from "date-fns"

export function formatTimestamp(ms: number): string {
  return format(new Date(ms), "yyyy-MM-dd HH:mm:ss")
}

export function formatScore(score: number): string {
  return score.toFixed(1)
}

export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) {
    return str
  }

  return `${str.slice(0, Math.max(0, maxLen - 3))}...`
}
