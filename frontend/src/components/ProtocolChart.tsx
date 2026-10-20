import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

interface ProtocolChartProps {
  protocols: Record<string, number>;
}

const COLORS: Record<string, string> = {
  TCP: "#3b82f6",
  UDP: "#14b8a6",
  ICMP: "#f59e0b",
  Other: "#94a3b8",
};

export default function ProtocolChart({ protocols }: ProtocolChartProps) {
  // Convert protocol counts into chart data.
  const chartData = Object.entries(protocols).map(([name, value]) => ({
    name,
    value,
  }));

  if (chartData.length === 0) {
    return <p>No protocol data available.</p>;
  }

  return (
    <div className="chart-wrapper">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="45%"
            innerRadius={60}
            outerRadius={90}
            paddingAngle={3}
          >
            {chartData.map((entry) => (
              <Cell
                key={entry.name}
                fill={COLORS[entry.name] ?? COLORS.Other}
              />
            ))}
          </Pie>

          <Tooltip
            contentStyle={{
              backgroundColor: "#151e30",
              border: "1px solid #334155",
              borderRadius: "8px",
              color: "#f1f5f9",
            }}
          />

          <Legend verticalAlign="bottom" iconType="circle" />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
