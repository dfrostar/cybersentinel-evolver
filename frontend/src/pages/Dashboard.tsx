import { useState, useEffect } from 'react'
import { api, AggregateMetrics, TournamentResult } from '../api/client'
import { MetricsCard } from '../components/MetricsCard'

export default function Dashboard() {
  const [metrics, setMetrics] = useState<AggregateMetrics | null>(null)
  const [latest, setLatest] = useState<TournamentResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  async function load() {
    try {
      const [m, t] = await Promise.all([api.getMetrics(), api.getTournaments()])
      setMetrics(m)
      setLatest(t.length > 0 ? t[0] : null)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  if (loading) return <div className="loading">Loading dashboard...</div>
  if (error) return <div className="error">Failed to load: {error}</div>
  if (!metrics) return null

  return (
    <div>
      <h2 style={{ marginBottom: '1.5rem', fontSize: '1.25rem' }}>Overview</h2>
      <div className="grid">
        <MetricsCard title="Scenarios" value={metrics.total_scenarios} />
        <MetricsCard title="Tournaments" value={metrics.total_tournaments} />
        <MetricsCard title="Mutations" value={metrics.total_mutations} />
        <MetricsCard title="Avg Win Rate" value={`${(metrics.avg_win_rate * 100).toFixed(1)}%`} />
        <MetricsCard title="Cost Blocked" value={`$${metrics.total_cost_blocked.toFixed(2)}`} />
        <MetricsCard title="Cost Missed" value={`$${metrics.total_cost_missed.toFixed(2)}`} />
        <MetricsCard title="Abuse Types" value={metrics.unique_abuse_types} />
        <MetricsCard title="Source Feeds" value={metrics.unique_feeds} />
      </div>
      {latest && (
        <div className="card" style={{ maxWidth: 500 }}>
          <h3>Latest Tournament</h3>
          <p style={{ marginTop: '0.5rem' }}>
            <strong>{latest.detector_id}</strong> —{' '}
            {(latest.win_rate * 100).toFixed(1)}% win rate,{' '}
            {latest.scenario_count} scenarios
          </p>
          <p style={{ marginTop: '0.25rem', color: '#94a3b8' }}>
            Cost blocked: ${latest.cost_blocked.toFixed(2)} | Missed: ${latest.cost_missed.toFixed(2)}
          </p>
        </div>
      )}
      <div style={{ marginTop: '1.5rem', display: 'flex', gap: '1rem' }}>
        <button onClick={load}>Refresh</button>
        <button onClick={() => api.generateScenarios().then(load)}>Generate Scenarios</button>
        <button onClick={() => api.runTournament().then(load)}>Run Tournament</button>
      </div>
    </div>
  )
}
