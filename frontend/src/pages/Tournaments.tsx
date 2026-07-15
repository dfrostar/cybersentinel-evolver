import { useState, useEffect } from 'react'
import { api, TournamentResult } from '../api/client'

export default function Tournaments() {
  const [results, setResults] = useState<TournamentResult[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  async function load() {
    try {
      setResults(await api.getTournaments())
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  if (loading) return <div className="loading">Loading tournaments...</div>
  if (error) return <div className="error">Failed: {error}</div>

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.25rem' }}>Tournament History ({results.length})</h2>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <button onClick={() => api.runTournament().then(load)}>Run New</button>
          <button onClick={load}>Refresh</button>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>Run ID</th>
            <th>Detector</th>
            <th>Scenarios</th>
            <th>Detected</th>
            <th>Win Rate</th>
            <th>Cost Blocked</th>
            <th>Cost Missed</th>
          </tr>
        </thead>
        <tbody>
          {results.map((r) => (
            <tr key={r.run_id}>
              <td>{r.run_id.slice(0, 8)}</td>
              <td>{r.detector_id}</td>
              <td>{r.scenario_count}</td>
              <td>{r.detected_count}</td>
              <td>{(r.win_rate * 100).toFixed(1)}%</td>
              <td>${r.cost_blocked.toFixed(2)}</td>
              <td>${r.cost_missed.toFixed(2)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
