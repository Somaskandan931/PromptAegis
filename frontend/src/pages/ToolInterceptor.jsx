/**
 * LEGACY COMPONENT: ToolInterceptor
 * Superseded by the Dual-Plane Security Control Plane (GovernancePanel.jsx -> Plane B: Verification Lab).
 * Retained for backward-compatible reference only. Not referenced in active application routing.
 */

import { useEffect, useState, useCallback } from 'react'
import { PageHeader } from './Playground'
import { api } from '../api'

const CONFIGS = [
  { value: 'baseline', label: 'Baseline' },
  { value: 'permission', label: 'Permission' },
  { value: 'policy', label: 'Policy' },
  { value: 'full', label: 'Full' },
]

const DECISION_STYLE = {
  ALLOW: { background: 'var(--tier-safe-bg, #0f2e1f)', color: 'var(--tier-safe, #4ade80)', border: '1px solid var(--tier-safe, #4ade80)' },
  DENY: { background: 'var(--tier-high-bg, #2e0f0f)', color: 'var(--tier-high, #f87171)', border: '1px solid var(--tier-high, #f87171)' },
  REQUIRE_APPROVAL: { background: 'var(--tier-medium-bg, #2c2000)', color: 'var(--tier-medium, #facc15)', border: '1px solid var(--tier-medium, #facc15)' },
  RATE_LIMIT: { background: '#1a1200', color: '#fb923c', border: '1px solid #fb923c' },
}

function DecisionBadge({ decision }) {
  const s = DECISION_STYLE[decision] ?? { background: 'var(--surface-raised)', color: 'var(--text-muted)', border: '1px solid var(--border)' }
  return (
    <span style={{ ...styles.decisionBadge, ...s }}>{decision ?? '—'}</span>
  )
}

function RiskBar({ score }) {
  const pct = Math.min(Math.max((score ?? 0) / 10, 0), 1) * 100
  const color = pct >= 70 ? 'var(--tier-high, #f87171)' : pct >= 40 ? 'var(--tier-medium, #facc15)' : 'var(--tier-safe, #4ade80)'
  return (
    <div style={styles.riskBarWrap}>
      <div style={{ ...styles.riskBarFill, width: `${pct}%`, background: color }} />
      <span style={styles.riskBarLabel}>{(score ?? 0).toFixed(2)}</span>
    </div>
  )
}

function fmtTime(ts) {
  if (!ts) return '—'
  try { return new Date(ts).toLocaleTimeString() } catch { return ts }
}

export default function ToolInterceptor() {
  const [agents, setAgents] = useState([])
  const [tools, setTools] = useState([])
  const [config, setConfig] = useState('full')
  const [agentId, setAgentId] = useState('')
  const [toolName, setToolName] = useState('')
  const [argsJson, setArgsJson] = useState('{}')
  const [argsError, setArgsError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [resultError, setResultError] = useState(null)
  const [calls, setCalls] = useState([])
  const [callsLoading, setCallsLoading] = useState(false)

  const loadCallsLog = useCallback(async () => {
    setCallsLoading(true)
    try {
      const res = await api.getToolCalls(null, null, 20)
      setCalls(res.tool_calls ?? res.calls ?? res ?? [])
    } catch {
      // silently ignore
    } finally {
      setCallsLoading(false)
    }
  }, [])

  useEffect(() => {
    Promise.all([api.listAgents(), api.listTools()])
      .then(([agentsRes, toolsRes]) => {
        const agentList = agentsRes.agents ?? agentsRes ?? []
        const toolList = toolsRes.tools ?? toolsRes ?? []
        setAgents(agentList)
        setTools(toolList)
        if (agentList.length > 0) setAgentId(agentList[0].agent_id)
        if (toolList.length > 0) setToolName(toolList[0].name)
      })
      .catch(() => {})
    loadCallsLog()
  }, [loadCallsLog])

  const selectedTool = tools.find((t) => t.name === toolName)

  const riskBadgeStyle = (level) => {
    if (!level) return {}
    const l = level.toLowerCase()
    if (l === 'high') return { background: 'var(--tier-high-bg, #2e0f0f)', color: 'var(--tier-high, #f87171)' }
    if (l === 'medium') return { background: 'var(--tier-medium-bg, #2c2000)', color: 'var(--tier-medium, #facc15)' }
    return { background: 'var(--tier-safe-bg, #0f2e1f)', color: 'var(--tier-safe, #4ade80)' }
  }

  const handleSend = async () => {
    setResultError(null)
    setResult(null)

    let parsedArgs = {}
    try {
      parsedArgs = JSON.parse(argsJson)
      setArgsError(null)
    } catch {
      setArgsError('Invalid JSON in arguments field.')
      return
    }

    setLoading(true)
    try {
      const res = await api.intercept(agentId, toolName, parsedArgs, config)
      setResult(res)
      await loadCallsLog()
    } catch (e) {
      setResultError(e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <PageHeader
        eyebrow="Governance"
        title="Tool Interception Playground"
        subtitle="Send tool call requests through the governance gateway and observe the real-time decision."
      />

      <div style={styles.layout}>
        {/* ── Left: Config Panel ── */}
        <div style={styles.configPanel}>
          {/* Configuration */}
          <div style={styles.section}>
            <div style={styles.sectionTitle}>Configuration</div>
            <div style={styles.radioCol}>
              {CONFIGS.map((c) => (
                <label key={c.value} style={styles.radioRow}>
                  <input
                    type="radio"
                    name="config"
                    value={c.value}
                    checked={config === c.value}
                    onChange={() => setConfig(c.value)}
                  />
                  <span style={styles.radioText}>{c.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Agent */}
          <div style={styles.section}>
            <div style={styles.sectionTitle}>Agent</div>
            <select
              style={styles.select}
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
            >
              {agents.length === 0 && <option value="">No agents — seed defaults first</option>}
              {agents.map((a) => (
                <option key={a.agent_id} value={a.agent_id}>{a.name} ({a.role})</option>
              ))}
            </select>
          </div>

          {/* Tool */}
          <div style={styles.section}>
            <div style={styles.sectionTitle}>Tool</div>
            <select
              style={styles.select}
              value={toolName}
              onChange={(e) => setToolName(e.target.value)}
            >
              {tools.length === 0 && <option value="">No tools — seed defaults first</option>}
              {tools.map((t) => (
                <option key={t.tool_id ?? t.name} value={t.name}>
                  {t.name} [{t.risk_level}]
                </option>
              ))}
            </select>
            {selectedTool && (
              <div style={styles.toolMeta}>
                <span style={{ ...styles.riskPill, ...riskBadgeStyle(selectedTool.risk_level) }}>
                  {selectedTool.risk_level}
                </span>
                <span style={styles.toolCategory}>{selectedTool.category}</span>
                {selectedTool.requires_approval && (
                  <span style={styles.approvalPill}>Approval required</span>
                )}
              </div>
            )}
          </div>

          {/* Arguments */}
          <div style={styles.section}>
            <div style={styles.sectionTitle}>Arguments (JSON)</div>
            <textarea
              style={{ ...styles.textarea, borderColor: argsError ? 'var(--tier-high, #f87171)' : 'var(--border)' }}
              value={argsJson}
              onChange={(e) => setArgsJson(e.target.value)}
              rows={5}
              spellCheck={false}
              placeholder='{"key": "value"}'
            />
            {argsError && <div style={styles.fieldError}>{argsError}</div>}
          </div>

          <button
            style={styles.sendBtn}
            onClick={handleSend}
            disabled={loading || !agentId || !toolName}
          >
            {loading ? '⟳ Sending…' : '▶ Send to Gateway'}
          </button>

          {resultError && <div style={styles.errorMsg}>{resultError}</div>}
        </div>

        {/* ── Right: Result ── */}
        <div style={styles.resultCol}>
          {result ? (
            <div style={styles.resultCard}>
              <div style={styles.resultHeader}>
                <DecisionBadge decision={result.decision} />
                {result.latency_ms != null && (
                  <span style={styles.latencyPill}>{result.latency_ms.toFixed(1)} ms</span>
                )}
              </div>

              <div style={styles.resultRow}>
                <span style={styles.resultLabel}>Reason</span>
                <span style={styles.resultValue}>{result.reason ?? '—'}</span>
              </div>

              <div style={styles.resultRow}>
                <span style={styles.resultLabel}>Risk Score</span>
                <RiskBar score={result.risk_score} />
              </div>

              {result.policy_id && (
                <div style={styles.resultRow}>
                  <span style={styles.resultLabel}>Policy ID</span>
                  <span style={{ ...styles.resultValue, ...styles.mono }}>{result.policy_id}</span>
                </div>
              )}
            </div>
          ) : (
            <div style={styles.resultPlaceholder}>
              <div style={styles.placeholderIcon}>⚙</div>
              <div style={styles.placeholderText}>Send a request to see the gateway decision here.</div>
            </div>
          )}
        </div>
      </div>

      {/* ── Recent Tool Calls Table ── */}
      <div style={styles.recentSection}>
        <div style={styles.recentHeader}>
          <div style={styles.recentTitle}>Recent Tool Calls</div>
          <button style={styles.refreshBtn} onClick={loadCallsLog} disabled={callsLoading}>
            {callsLoading ? 'Loading…' : 'Refresh'}
          </button>
        </div>

        <div style={styles.tableWrap}>
          <table style={styles.table}>
            <thead>
              <tr>
                {['Time', 'Agent', 'Tool', 'Decision', 'Reason', 'Risk'].map((h) => (
                  <th key={h} style={styles.th}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {calls.length === 0 ? (
                <tr>
                  <td colSpan={6} style={styles.tdCenter}>
                    {callsLoading ? 'Loading…' : 'No tool calls logged yet.'}
                  </td>
                </tr>
              ) : calls.map((c, i) => (
                <tr key={c.call_id ?? i} style={styles.tr}>
                  <td style={{ ...styles.td, ...styles.mono, fontSize: 11.5 }}>{fmtTime(c.timestamp)}</td>
                  <td style={styles.td}>{c.agent_id ?? '—'}</td>
                  <td style={{ ...styles.td, fontWeight: 600 }}>{c.tool_name ?? '—'}</td>
                  <td style={styles.td}><DecisionBadge decision={c.decision} /></td>
                  <td style={{ ...styles.td, color: 'var(--text-muted)', fontSize: 12, maxWidth: 240 }}>
                    {c.reason ?? '—'}
                  </td>
                  <td style={{ ...styles.td, ...styles.mono, fontSize: 12 }}>
                    {c.risk_score != null ? c.risk_score.toFixed(2) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

const styles = {
  layout: { display: 'grid', gridTemplateColumns: '340px 1fr', gap: 20, marginBottom: 28, alignItems: 'start' },
  configPanel: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: 20,
    display: 'flex',
    flexDirection: 'column',
    gap: 0,
  },
  section: { marginBottom: 18 },
  sectionTitle: { fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 },
  radioCol: { display: 'flex', flexDirection: 'column', gap: 6 },
  radioRow: { display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' },
  radioText: { fontSize: 13.5, color: 'var(--text-primary)' },
  select: {
    width: '100%',
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 13,
    padding: '8px 10px',
    borderRadius: 'var(--radius-sm)',
    outline: 'none',
    cursor: 'pointer',
  },
  toolMeta: { display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap', alignItems: 'center' },
  riskPill: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10.5,
    fontWeight: 700,
    padding: '2px 7px',
    borderRadius: 999,
  },
  toolCategory: { fontSize: 11.5, color: 'var(--text-muted)' },
  approvalPill: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10.5,
    fontWeight: 700,
    padding: '2px 7px',
    borderRadius: 999,
    background: 'var(--tier-medium-bg, #2c2000)',
    color: 'var(--tier-medium, #facc15)',
  },
  textarea: {
    width: '100%',
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 12.5,
    fontFamily: 'var(--font-mono)',
    padding: '10px 12px',
    borderRadius: 'var(--radius-sm)',
    resize: 'vertical',
    outline: 'none',
    boxSizing: 'border-box',
  },
  fieldError: { marginTop: 6, color: 'var(--tier-high, #f87171)', fontSize: 12 },
  sendBtn: {
    width: '100%',
    background: 'var(--signal)',
    border: 'none',
    color: '#04211D',
    fontWeight: 800,
    fontSize: 14,
    padding: '11px 0',
    borderRadius: 999,
    cursor: 'pointer',
    marginBottom: 10,
  },
  errorMsg: {
    color: 'var(--tier-high, #f87171)',
    background: 'var(--tier-high-bg, #2e0f0f)',
    padding: '10px 14px',
    borderRadius: 'var(--radius-sm)',
    fontSize: 13,
    marginTop: 8,
  },
  resultCol: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: 24,
    minHeight: 300,
    display: 'flex',
    flexDirection: 'column',
  },
  resultCard: { display: 'flex', flexDirection: 'column', gap: 16 },
  resultHeader: { display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' },
  decisionBadge: {
    fontFamily: 'var(--font-mono)',
    fontSize: 13,
    fontWeight: 800,
    padding: '6px 16px',
    borderRadius: 999,
    letterSpacing: 0.5,
  },
  latencyPill: {
    fontFamily: 'var(--font-mono)',
    fontSize: 12,
    color: 'var(--text-muted)',
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    padding: '4px 10px',
    borderRadius: 999,
  },
  resultRow: { display: 'flex', alignItems: 'flex-start', gap: 14 },
  resultLabel: { minWidth: 90, fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', paddingTop: 2 },
  resultValue: { fontSize: 13.5, color: 'var(--text-primary)', lineHeight: 1.5 },
  riskBarWrap: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    background: 'var(--bg)',
    border: '1px solid var(--border-soft)',
    borderRadius: 999,
    height: 18,
    overflow: 'hidden',
    padding: '0 0',
    position: 'relative',
  },
  riskBarFill: { height: '100%', borderRadius: 999, transition: 'width 0.3s ease', minWidth: 2 },
  riskBarLabel: {
    position: 'absolute',
    right: 10,
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    color: 'var(--text-muted)',
  },
  resultPlaceholder: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 12,
    color: 'var(--text-dim)',
    minHeight: 260,
  },
  placeholderIcon: { fontSize: 32, opacity: 0.3 },
  placeholderText: { fontSize: 13.5, textAlign: 'center', maxWidth: 280, lineHeight: 1.6 },
  recentSection: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: 22,
  },
  recentHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 },
  recentTitle: { fontSize: 15, fontWeight: 700 },
  refreshBtn: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 12.5,
    padding: '7px 14px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
  },
  tableWrap: { overflowX: 'auto' },
  table: { width: '100%', borderCollapse: 'collapse', fontSize: 13 },
  th: {
    textAlign: 'left',
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    fontWeight: 700,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.06em',
    padding: '8px 12px',
    borderBottom: '1px solid var(--border)',
  },
  td: { padding: '10px 12px', verticalAlign: 'middle' },
  tdCenter: { padding: '20px 12px', textAlign: 'center', color: 'var(--text-dim)', fontSize: 13 },
  tr: { borderBottom: '1px solid var(--border-soft)' },
  mono: { fontFamily: 'var(--font-mono)' },
}
