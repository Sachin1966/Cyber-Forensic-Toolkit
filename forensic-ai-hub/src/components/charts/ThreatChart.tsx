import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ThreatTrendItem } from "@/lib/api";

interface ThreatChartProps {
  data: ThreatTrendItem[];
  title?: string;
}

export function ThreatChart({ data, title = "Threat Trend Analysis" }: ThreatChartProps) {
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-card/95 backdrop-blur-xl border border-border rounded-lg p-4 shadow-lg">
          <p className="font-medium text-foreground mb-2">{label}</p>
          {payload.map((entry: any, index: number) => (
            <p
              key={index}
              className="text-sm"
              style={{ color: entry.color }}
            >
              {entry.name}: {entry.value}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <Card variant="cyber" className="h-full">
      <CardHeader>
        <CardTitle className="text-lg">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              data={data}
              margin={{ top: 10, right: 30, left: 0, bottom: 0 }}
            >
              <defs>
                <linearGradient id="colorSafe" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(142, 76%, 45%)" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="hsl(142, 76%, 45%)" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorWarning" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(45, 100%, 50%)" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="hsl(45, 100%, 50%)" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorDanger" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(0, 84%, 60%)" stopOpacity={0.8} />
                  <stop offset="95%" stopColor="hsl(0, 84%, 60%)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(222, 30%, 18%)" />
              <XAxis
                dataKey="date"
                stroke="hsl(215, 20%, 55%)"
                fontSize={12}
                tickLine={false}
              />
              <YAxis
                stroke="hsl(215, 20%, 55%)"
                fontSize={12}
                tickLine={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Legend
                wrapperStyle={{ paddingTop: "20px" }}
                formatter={(value) => (
                  <span className="text-foreground text-sm">{value}</span>
                )}
              />
              <Area
                type="monotone"
                dataKey="safe"
                name="Safe"
                stroke="hsl(142, 76%, 45%)"
                fillOpacity={1}
                fill="url(#colorSafe)"
              />
              <Area
                type="monotone"
                dataKey="warning"
                name="Warning"
                stroke="hsl(45, 100%, 50%)"
                fillOpacity={1}
                fill="url(#colorWarning)"
              />
              <Area
                type="monotone"
                dataKey="danger"
                name="Critical"
                stroke="hsl(0, 84%, 60%)"
                fillOpacity={1}
                fill="url(#colorDanger)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
