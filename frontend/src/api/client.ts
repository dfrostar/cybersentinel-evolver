/**
 * API client for the CyberSentinel Evolver backend.
 *
 * Backend is a Python FastAPI server with endpoints:
 *   GET  /api/tournaments          — list tournament results
 *   GET  /api/scenarios            — list scenarios
 *   GET  /api/gap-analysis         — list gap analysis findings
 *   GET  /api/metrics              — aggregate metrics
 *   POST /api/tournaments/run      — trigger a new tournament
 *   POST /api/scenarios/generate   — trigger scenario generation
 *   POST /api/self-prompt          — trigger self-prompting
 *   POST /api/gap-analysis/run     — trigger gap analysis
 *   GET  /health                   — liveness check
 */

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api'

async function fetchJSON<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    throw new Error(`API ${url}: ${res.status} ${res.statusText}`)
  }
  return res.json()
}

export interface TournamentResult {
  run_id: string
  detector_id: string
  scenario_count: number
  detected_count: number
  win_rate: number
  cost_blocked: number
  cost_missed: number
  ran_at: number
}

export interface Scenario {
  id: string
  name: string
  abuse_type: string
  identity_source: string
  source_feed: string
  generation: number
  mutation_depth: number
}

export interface GapFinding {
  id: string
  analysis_type: string
  findings: string
  recommended_prompts: string
  created_at: number
}

export interface AggregateMetrics {
  total_scenarios: number
  total_tournaments: number
  total_mutations: number
  avg_win_rate: number
  total_cost_blocked: number
  total_cost_missed: number
  unique_abuse_types: number
  unique_feeds: number
}

export const api = {
  getTournaments: () => fetchJSON<TournamentResult[]>('/tournaments'),
  getScenarios: () => fetchJSON<Scenario[]>('/scenarios'),
  getGapAnalysis: () => fetchJSON<GapFinding[]>('/gap-analysis'),
  getMetrics: () => fetchJSON<AggregateMetrics>('/metrics'),
  runTournament: () => fetchJSON<{ status: string }>('/tournaments/run', { method: 'POST' }),
  generateScenarios: () => fetchJSON<{ status: string; count: number }>('/scenarios/generate', { method: 'POST' }),
  runSelfPrompt: (trigger: string, context: string) =>
    fetchJSON<{ status: string }>('/self-prompt', {
      method: 'POST',
      body: JSON.stringify({ trigger, context }),
    }),
  runGapAnalysis: (type: string) =>
    fetchJSON<{ status: string }>('/gap-analysis/run', {
      method: 'POST',
      body: JSON.stringify({ type }),
    }),
}
