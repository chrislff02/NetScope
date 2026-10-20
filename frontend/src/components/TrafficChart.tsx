import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

interface TrafficChartProps {
  traffic: Record<string, { packets: number; bytes: number }>;
}

export default function TrafficChart({ traffic }: TrafficChartProps) {
  // Convert the API's timestamp dictionary into chart data.
  const chartData = Object.entries(traffic).map(([timestamp, values]) => ({
    time: timestamp.slice(11, 19),
    bytes: values.bytes,
    packets: values.packets,
  }));

  if (chartData.length === 0) {
    return <p>No traffic data available.</p>;
  }

  return (
    <div className="chart-wrapper">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={chartData}
          margin={{ top: 10, right: 15, left: 0, bottom: 0 }}
        >
          <defs>
            <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity={0.35} />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity={0} />
            </linearGradient>
          </defs>

          <CartesianGrid
            stroke="#334155"
            strokeDasharray="3 3"
            vertical={false}
          />

          <XAxis
            dataKey="time"
            stroke="#94a3b8"
            tick={{ fontSize: 11 }}
            minTickGap={30}
          />

          <YAxis stroke="#94a3b8" tick={{ fontSize: 11 }} width={45} />

          <Tooltip
            contentStyle={{
              backgroundColor: "#151e30",
              border: "1px solid #334155",
              borderRadius: "8px",
              color: "#f1f5f9",
            }}
          />

          <Area
            type="monotone"
            dataKey="bytes"
            name="Bytes per second"
            stroke="#60a5fa"
            strokeWidth={2}
            fill="url(#trafficGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
