import { useState } from "react"
import type { ReactNode } from "react"
import { Activity, AlertTriangle, Loader2, RefreshCw, ShieldX, TrendingUp } from "lucide-react"
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from "recharts"

import { Header } from "@/components/layout/Header"
import { ErrorState } from "@/components/common/ErrorState"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { truncate } from "@/lib/formatters"
import { useDashboard, type DashboardPreset } from "@/hooks/useDashboard"

const PRESETS: DashboardPreset[] = ["1h", "6h", "24h", "7d"]

function KpiCard({
  label,
  value,
  icon,
  loading,
}: {
  label: string
  value: string
  icon: ReactNode
  loading: boolean
}) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
      <div className="mb-3 flex items-center justify-between">
        <p className="text-xs text-zinc-400">{label}</p>
        {icon}
      </div>
      {loading ? (
        <Skeleton className="h-8 w-24 bg-zinc-800" />
      ) : (
        <p className="text-[28px] font-semibold leading-none text-zinc-100">{value}</p>
      )}
    </div>
  )
}

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
      <h3 className="mb-4 text-sm font-medium text-zinc-200">{title}</h3>
      {children}
    </div>
  )
}

export function DashboardPage() {
  const [preset, setPreset] = useState<DashboardPreset>("24h")
  const { data, isLoading, isError, refetch, isFetching } = useDashboard(preset)

  if (isError) {
    return (
      <section>
        <Header title="Dashboard" />
        <ErrorState
          message="Could not connect to WAF API"
          detail="Check that the proxy service is running on port 8090."
          onRetry={() => {
            void refetch()
          }}
        />
      </section>
    )
  }

  return (
    <section>
      <Header
        title="Dashboard"
        actions={
          <TooltipProvider>
            <div className="flex items-center gap-2">
              {PRESETS.map((value) => (
                <Button
                  key={value}
                  variant="outline"
                  className={value === preset ? "bg-blue-600 text-white hover:bg-blue-500" : "text-zinc-300"}
                  onClick={() => setPreset(value)}
                >
                  {value}
                </Button>
              ))}

              <Tooltip>
                <TooltipTrigger render={<span />}>
                  <Button
                    variant="outline"
                    size="icon-sm"
                    onClick={() => {
                      void refetch()
                    }}
                    aria-label="Refresh data"
                  >
                    {isFetching ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Refresh data</TooltipContent>
              </Tooltip>
            </div>
          </TooltipProvider>
        }
      />

      <div className="space-y-4 px-8 py-6">
        <div className="grid grid-cols-4 gap-4">
          <KpiCard
            label="Total Requests"
            value={String(data.totalRequests)}
            loading={isLoading}
            icon={<Activity className="size-4 text-zinc-400" />}
          />
          <KpiCard
            label="Blocked"
            value={String(data.blocked)}
            loading={isLoading}
            icon={<ShieldX className="size-4 text-zinc-400" />}
          />
          <KpiCard
            label="Block Rate"
            value={`${data.blockRate}%`}
            loading={isLoading}
            icon={<TrendingUp className="size-4 text-zinc-400" />}
          />
          <KpiCard
            label="Alerts (Log Only)"
            value={String(data.logOnly)}
            loading={isLoading}
            icon={<AlertTriangle className="size-4 text-zinc-400" />}
          />
        </div>

        <ChartCard title="Block Rate Over Time">
          {data.timeSeries.every((point) => point.blocked === 0) ? (
            <div className="flex h-[240px] flex-col items-center justify-center text-center">
              <p className="text-sm text-zinc-200">No data for this period</p>
              <p className="text-xs text-zinc-400">Select a longer time window or wait for traffic to arrive.</p>
            </div>
          ) : (
            <div className="h-[240px]">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data.timeSeries}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                  <XAxis dataKey="label" stroke="#a1a1aa" tick={{ fontSize: 12 }} />
                  <YAxis stroke="#a1a1aa" tick={{ fontSize: 12 }} allowDecimals={false} />
                  <RechartsTooltip
                    contentStyle={{
                      backgroundColor: "#18181b",
                      border: "1px solid #3f3f46",
                      borderRadius: "8px",
                    }}
                    labelStyle={{ color: "#e4e4e7" }}
                    itemStyle={{ color: "#d4d4d8" }}
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    stroke="#3b82f6"
                    fill="#2563eb"
                    fillOpacity={0.2}
                    strokeWidth={2}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </ChartCard>

        <div className="grid grid-cols-2 gap-4">
          <ChartCard title="Top 5 Rules">
            {data.topRules.length === 0 ? (
              <div className="flex h-[200px] items-center justify-center text-sm text-zinc-400">No data</div>
            ) : (
              <div className="h-[200px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={data.topRules.map((item) => ({ ...item, shortName: truncate(item.name, 20) }))} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                    <XAxis type="number" stroke="#a1a1aa" tick={{ fontSize: 12 }} allowDecimals={false} />
                    <YAxis type="category" dataKey="shortName" width={130} stroke="#a1a1aa" tick={{ fontSize: 12 }} />
                    <RechartsTooltip
                      contentStyle={{
                        backgroundColor: "#18181b",
                        border: "1px solid #3f3f46",
                        borderRadius: "8px",
                      }}
                      labelStyle={{ color: "#e4e4e7" }}
                      itemStyle={{ color: "#d4d4d8" }}
                    />
                    <Bar dataKey="count" fill="#2563eb" radius={[4, 4, 4, 4]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </ChartCard>

          <ChartCard title="Top 5 Paths">
            {data.topPaths.length === 0 ? (
              <div className="flex h-[200px] items-center justify-center text-sm text-zinc-400">No data</div>
            ) : (
              <div className="h-[200px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={data.topPaths.map((item) => ({ ...item, shortName: truncate(item.name, 24) }))} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                    <XAxis type="number" stroke="#a1a1aa" tick={{ fontSize: 12 }} allowDecimals={false} />
                    <YAxis type="category" dataKey="shortName" width={150} stroke="#a1a1aa" tick={{ fontSize: 12 }} />
                    <RechartsTooltip
                      contentStyle={{
                        backgroundColor: "#18181b",
                        border: "1px solid #3f3f46",
                        borderRadius: "8px",
                      }}
                      labelStyle={{ color: "#e4e4e7" }}
                      itemStyle={{ color: "#d4d4d8" }}
                    />
                    <Bar dataKey="count" fill="#52525b" radius={[4, 4, 4, 4]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </ChartCard>
        </div>
      </div>
    </section>
  )
}
