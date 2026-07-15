interface MetricsCardProps {
  title: string
  value: string | number
}

export function MetricsCard({ title, value }: MetricsCardProps) {
  return (
    <div className="card">
      <h3>{title}</h3>
      <div className="value">{value}</div>
    </div>
  )
}
