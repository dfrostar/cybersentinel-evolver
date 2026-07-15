import { useState, useEffect } from 'react'
import { api, Scenario } from '../api/client'

export default function Scenarios() {
  const [scenarios, setScenarios] = useState<Scenario[]>([])
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  async function load() {
    try {
      setScenarios(await api.getScenarios())
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  if (loading) return <div className="loading">Loading scenarios...</div>
  if (error) return <div className="error">Failed: {error}</div>

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.25rem' }}>Scenarios ({scenarios.length})</h2>
        <button onClick={load}>Refresh</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Abuse Type</th>
            <th>Identity</th>
            <th>Feed</th>
            <th>Gen</th>
            <th>Depth</th>
          </tr>
        </thead>
        <tbody>
          {scenarios.map((s) => (
            <tr key={s.id}>
              <td>{s.name}</td>
              <td>{s.abuse_type}</td>
              <td>{s.identity_source}</td>
              <td>{s.source_feed}</td>
              <td>{s.generation}</td>
              <td>{s.mutation_depth}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
