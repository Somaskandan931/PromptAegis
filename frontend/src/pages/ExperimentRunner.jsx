import { useEffect, useState, useMemo, useCallback } from 'react'
import { PageHeader } from './Playground'
import { api } from '../api'

// ─── Benchmark Configurations ───────────────────────────────────────────────

const CONFIGURATIONS = [
  {
    id: 'baseline',
    label: 'NO GOVERNANCE',
    tag: 'Control Baseline',
    desc: 'No RBAC, policy, or gateway enforcement.',
    details: 'Tool calls pass through without permission checks, policy validation, or rate limits.',
  },
  {
    id: 'permission',
    label: 'RBAC ONLY',
    tag: 'Identity Boundary',
    desc: 'Authorization and permission checks only.',
    details: 'Enforces agent-to-tool role-based access matrix; parameter invariants and rate limits inactive.',
  },
  {
    id: 'policy',
    label: 'POLICY ONLY',
    tag: 'Invariant Filter',
    desc: 'Parameter and policy enforcement only.',
    details: 'Validates argument constraints and invariants; role permission checks inactive.',
  },
  {
    id: 'full',
    label: 'FULL GOVERNANCE',
    tag: 'Complete Reference Monitor',
    desc: 'Rate limiting + RBAC + canonicalization + policy + risk/approval + structured audit.',
    details: 'All PromptAegis sequential mediation controls active with comprehensive audit recording.',
  },
]

// ─── Scenario Categories ───────────────────────────────────────────────────

const SCENARIO_CATEGORIES = [
  {
    id: 'unauthorized_tool',
    label: 'Unauthorized Tool Use',
    type: 'Attack',
    desc: 'Proposals invoking capabilities outside the agent’s assigned scope.',
  },
  {
    id: 'privilege_escalation',
    label: 'Privilege Escalation',
    type: 'Attack',
    desc: 'Attempts by low-privileged agents to perform administrative operations.',
  },
  {
    id: 'prompt_injection',
    label: 'Prompt Injection',
    type: 'Attack',
    desc: 'Adversarial inputs attempting to hijack tool selection or execution context.',
  },
  {
    id: 'parameter_manipulation',
    label: 'Parameter Manipulation',
    type: 'Attack',
    desc: 'Malformed arguments, path traversal, or out-of-boundary values.',
  },
  {
    id: 'excessive_calls',
    label: 'Excessive Invocations',
    type: 'Attack',
    desc: 'High-frequency tool invocation bursts to test rate-limiting thresholds.',
  },
  {
    id: 'legitimate',
    label: 'Legitimate Tasks',
    type: 'Benign',
    desc: 'Authorized, benign agent tasks to measure task completion and false positives.',
  },
]

const SAMPLE_SIZE_OPTIONS = [
  { value: 0, label: 'All Scenarios (Standard Benchmark)' },
  { value: 10, label: '10 scenarios (Fast Smoke Test)' },
  { value: 50, label: '50 scenarios (Quick Sample)' },
  { value: 100, label: '100 scenarios (Representative Subset)' },
]

// ─── Timestamp Formatting Helper ───────────────────────────────────────────

function formatTimestamp(ts) {
  if (!ts) return 'Timestamp unavailable'
  // Convert Unix seconds to milliseconds if needed
  const ms = typeof ts === 'number' && ts < 1e11 ? ts * 1000 : Number(ts)
  if (isNaN(ms) || ms <= 0) return 'Timestamp unavailable'
  try {
    const d = new Date(ms)
    // Guard against year-1970 epoch fallback bugs
    if (isNaN(d.getTime()) || d.getFullYear() < 2000) {
      return 'Timestamp unavailable'
    }
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return 'Timestamp unavailable'
  }
}

// ─── Human-Readable Run Naming Helper ──────────────────────────────────────

function getHumanRunName(run, allRuns = []) {
  if (run.description && !run.description.startsWith('run_') && !run.description.includes('configuration experiment')) {
    return run.description
  }
  const configObj = CONFIGURATIONS.find((c) => c.id === run.configuration)
  const configName = configObj ? configObj.label : run.configuration.toUpperCase()
  
  // Find index among runs with same configuration
  const sameConfigRuns = allRuns.filter((r) => r.configuration === run.configuration)
  const chronologicalIndex = sameConfigRuns.length - sameConfigRuns.findIndex((r) => r.run_id === run.run_id)
  return `${configName} #${chronologicalIndex > 0 ? chronologicalIndex : 1}`
}

// ─── Main Component ────────────────────────────────────────────────────────

export default function ExperimentRunner() {
  // Evaluation Configuration Form
  const [selectedConfig, setSelectedConfig] = useState('full')
  const [selectedCategories, setSelectedCategories] = useState([])
  const [scenarioCountMode, setScenarioCountMode] = useState(0) // 0 = all
  const [customScenarioCount, setCustomScenarioCount] = useState('')

  // Execution State
  const [running, setRunning] = useState(false)
  const [runError, setRunError] = useState(null)
  const [latestResult, setLatestResult] = useState(null)

  // Experiment History
  const [history, setHistory] = useState([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [expandedRunId, setExpandedRunId] = useState(null)
  const [expandedData, setExpandedData] = useState({})

  // Fetch History
  const loadHistory = useCallback(async () => {
    setHistoryLoading(true)
    try {
      const res = await api.listExperiments()
      const runs = res.experiments ?? res ?? []
      setHistory(Array.isArray(runs) ? runs : [])
    } catch {
      // Ignore network errors on background refresh
    } finally {
      setHistoryLoading(false)
    }
  }, [])

  useEffect(() => {
    loadHistory()
  }, [loadHistory])

  // Category Toggle
  const toggleCategory = (catId) => {
    setSelectedCategories((prev) =>
      prev.includes(catId) ? prev.filter((id) => id !== catId) : [...prev, catId]
    )
  }

  const selectAllCategories = () => {
    setSelectedCategories([])
  }

  // Execute Benchmark
  const handleRunBenchmark = async () => {
    setRunning(true)
    setRunError(null)

    const effectiveCount = scenarioCountMode === 'custom'
      ? Math.max(0, parseInt(customScenarioCount, 10) || 0)
      : scenarioCountMode

    try {
      const res = await api.runExperiment(
        selectedConfig,
        '',
        selectedCategories,
        effectiveCount
      )
      setLatestResult(res)
      await loadHistory()
    } catch (err) {
      // If benchmark requires initial data setup, seamlessly initialize and retry once
      if (err.message && err.message.toLowerCase().includes('seed')) {
        try {
          await api.seedDefaults()
          const retryRes = await api.runExperiment(
            selectedConfig,
            '',
            selectedCategories,
            effectiveCount
          )
          setLatestResult(retryRes)
          await loadHistory()
          return
        } catch (retryErr) {
          setRunError(`Benchmark execution error: ${retryErr.message}`)
        }
      } else {
        setRunError(`Benchmark execution error: ${err.message}`)
      }
    } finally {
      setRunning(false)
    }
  }

  // Expand Run Details
  const handleToggleExpand = async (runId) => {
    if (expandedRunId === runId) {
      setExpandedRunId(null)
      return
    }
    setExpandedRunId(runId)
    if (!expandedData[runId]) {
      try {
        const details = await api.getExperiment(runId)
        setExpandedData((prev) => ({ ...prev, [runId]: details }))
      } catch (e) {
        setExpandedData((prev) => ({ ...prev, [runId]: { error: e.message } }))
      }
    }
  }

  // Derive latest comparison table from historical runs
  const comparisonData = useMemo(() => {
    return CONFIGURATIONS.map((cfg) => {
      // Find the most recent completed run for this configuration
      const run = history.find(
        (r) => r.configuration === cfg.id && (r.status === 'completed' || r.metrics?.total_scenarios)
      )
      const m = run?.metrics ?? run?.results ?? null
      return {
        id: cfg.id,
        label: cfg.label,
        tag: cfg.tag,
        run: run || null,
        asr: m?.asr ?? m?.attack_success_rate,
        ltcr: m?.ltcr ?? m?.legitimate_task_completion_rate,
        medianLatency: m?.latency_median_ms ?? m?.latency?.median ?? null,
        totalScenarios: run?.total_scenarios ?? m?.total_scenarios ?? null,
        completedAt: run?.completed_at || run?.started_at,
      }
    })
  }, [history])

  const activeResult = latestResult || (history.length > 0 ? history[0] : null)
  const activeMetrics = activeResult?.metrics ?? activeResult?.results ?? null

  return (
    <div style={styles.container}>
      {/* ── Page Header ── */}
      <PageHeader
        eyebrow="Scientific Evaluation"
        title="Research Benchmark"
        subtitle="Evaluate PromptAegis security configurations against controlled attack and legitimate-task scenarios."
      />

      {/* ── Explanatory Concept Card ── */}
      <div style={styles.explainerCard}>
        <div style={styles.explainerHeader}>
          <span style={styles.explainerIcon}>🔬</span>
          <span style={styles.explainerTitle}>What does this do?</span>
        </div>
        <p style={styles.explainerBody}>
          <strong>Research Benchmark</strong> runs the selected benchmark scenarios under a chosen governance configuration and measures <strong>Attack Success Rate (ASR)</strong>, <strong>Legitimate Task Completion Rate (LTCR)</strong>, and execution latency.
        </p>
        <div style={styles.metricDefinitionRow}>
          <div style={styles.definitionPill}>
            <span style={styles.defBadgeRed}>ASR (Attack Success Rate)</span>
            <span style={styles.defText}>Percentage of attack scenarios that bypassed controls. <em>Lower is better (0.0% is optimal).</em></span>
          </div>
          <div style={styles.definitionPill}>
            <span style={styles.defBadgeGreen}>LTCR (Legitimate Completion)</span>
            <span style={styles.defText}>Percentage of authorized benign tasks that executed successfully. <em>Higher is better (100.0% is optimal).</em></span>
          </div>
        </div>
      </div>

      {/* ── Section 1: What Are You Evaluating? ── */}
      <div style={styles.sectionCard}>
        <div style={styles.sectionHeaderRow}>
          <div>
            <div style={styles.sectionNumber}>SECTION 1</div>
            <div style={styles.sectionTitle}>What Are You Evaluating?</div>
          </div>
          <div style={styles.helperCallout}>
            <span style={{ fontSize: 13, marginRight: 6 }}>💡</span>
            <span><strong>Why compare configurations?</strong> These configurations isolate the contribution of individual governance controls.</span>
          </div>
        </div>

        <div style={styles.configGrid}>
          {CONFIGURATIONS.map((cfg) => {
            const isSelected = selectedConfig === cfg.id
            return (
              <div
                key={cfg.id}
                style={{
                  ...styles.configCard,
                  ...(isSelected ? styles.configCardSelected : {}),
                }}
                onClick={() => setSelectedConfig(cfg.id)}
              >
                <div style={styles.configCardTop}>
                  <div style={styles.configRadio}>
                    <input
                      type="radio"
                      name="eval-config"
                      checked={isSelected}
                      onChange={() => setSelectedConfig(cfg.id)}
                      style={{ cursor: 'pointer' }}
                    />
                  </div>
                  <span style={styles.configTag}>{cfg.tag}</span>
                </div>
                <div style={styles.configHeading}>{cfg.label}</div>
                <div style={styles.configDesc}>{cfg.desc}</div>
                <div style={styles.configDetails}>{cfg.details}</div>
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Section 2: Benchmark Scenarios ── */}
      <div style={styles.sectionCard}>
        <div style={styles.sectionHeaderRow}>
          <div>
            <div style={styles.sectionNumber}>SECTION 2</div>
            <div style={styles.sectionTitle}>Benchmark Scenarios</div>
            <div style={styles.sectionSubtitle}>Choose which benchmark scenario categories to evaluate.</div>
          </div>
          <div>
            <button
              style={styles.textActionBtn}
              onClick={selectAllCategories}
            >
              {selectedCategories.length === 0 ? '✓ All Categories Selected' : 'Select All Categories'}
            </button>
          </div>
        </div>

        <div style={styles.categoryGrid}>
          {SCENARIO_CATEGORIES.map((cat) => {
            const isChecked = selectedCategories.length === 0 || selectedCategories.includes(cat.id)
            const isExplicit = selectedCategories.includes(cat.id)
            return (
              <label
                key={cat.id}
                style={{
                  ...styles.categoryCard,
                  ...(isChecked ? styles.categoryCardChecked : {}),
                }}
              >
                <div style={styles.categoryCardTop}>
                  <input
                    type="checkbox"
                    checked={isChecked}
                    onChange={() => toggleCategory(cat.id)}
                    style={{ cursor: 'pointer' }}
                  />
                  <span
                    style={{
                      ...styles.categoryTypeBadge,
                      background: cat.type === 'Attack' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(74, 222, 128, 0.15)',
                      color: cat.type === 'Attack' ? 'var(--tier-high, #f87171)' : 'var(--tier-safe, #4ade80)',
                    }}
                  >
                    {cat.type}
                  </span>
                </div>
                <div style={styles.categoryName}>{cat.label}</div>
                <div style={styles.categoryDesc}>{cat.desc}</div>
              </label>
            )
          })}
        </div>

        {/* Scenario Sample Count Selector */}
        <div style={styles.sampleSelectorBox}>
          <div style={styles.sampleLabel}>Evaluation Scope & Scenario Count:</div>
          <div style={styles.sampleOptionsRow}>
            {SAMPLE_SIZE_OPTIONS.map((opt) => (
              <label key={opt.value} style={styles.sampleRadioLabel}>
                <input
                  type="radio"
                  name="scenario-count"
                  checked={scenarioCountMode === opt.value}
                  onChange={() => setScenarioCountMode(opt.value)}
                />
                <span>{opt.label}</span>
              </label>
            ))}
            <label style={styles.sampleRadioLabel}>
              <input
                type="radio"
                name="scenario-count"
                checked={scenarioCountMode === 'custom'}
                onChange={() => setScenarioCountMode('custom')}
              />
              <span>Custom Count</span>
            </label>
            {scenarioCountMode === 'custom' && (
              <input
                type="number"
                min="1"
                max="600"
                placeholder="e.g. 25"
                value={customScenarioCount}
                onChange={(e) => setCustomScenarioCount(e.target.value)}
                style={styles.customCountInput}
              />
            )}
          </div>
        </div>
      </div>

      {/* ── Section 3: Run Evaluation ── */}
      <div style={styles.sectionCard}>
        <div style={styles.sectionHeaderRow}>
          <div>
            <div style={styles.sectionNumber}>SECTION 3</div>
            <div style={styles.sectionTitle}>Run Evaluation</div>
          </div>
        </div>

        <div style={styles.runActionBox}>
          <div>
            <button
              style={{
                ...styles.primaryRunBtn,
                ...(running ? styles.primaryRunBtnDisabled : {}),
              }}
              onClick={handleRunBenchmark}
              disabled={running}
            >
              {running ? (
                <span style={styles.runningFlex}>
                  <span style={styles.spinner}>⟳</span>
                  Evaluating Benchmark Scenarios…
                </span>
              ) : (
                '▶ Run Benchmark'
              )}
            </button>
            <div style={styles.runSupportText}>
              Runs the selected configuration against the selected benchmark scenarios and records the resulting security decisions for analysis.
            </div>
          </div>

          <div style={styles.runConfigSummaryPill}>
            <div style={styles.runSummaryHeading}>Target Configuration:</div>
            <div style={styles.runSummaryValue}>
              {CONFIGURATIONS.find((c) => c.id === selectedConfig)?.label}
            </div>
            <div style={styles.runSummaryCategories}>
              {selectedCategories.length === 0
                ? 'All 6 Scenario Categories'
                : `${selectedCategories.length} Categories Selected`}
            </div>
          </div>
        </div>

        {runError && (
          <div style={styles.errorBanner}>
            <span style={{ fontSize: 16 }}>⚠️</span>
            <span>{runError}</span>
          </div>
        )}
      </div>

      {/* ── Section 4: Latest Benchmark Result ── */}
      {activeResult && (
        <div style={styles.latestResultCard}>
          <div style={styles.latestResultHeader}>
            <div>
              <div style={styles.latestResultEyebrow}>EVALUATION COMPLETE</div>
              <div style={styles.latestResultTitle}>Latest Benchmark Result</div>
            </div>
            <div style={styles.latestResultConfigBadge}>
              {CONFIGURATIONS.find((c) => c.id === activeResult.configuration)?.label || activeResult.configuration}
            </div>
          </div>

          <div style={styles.resultOverviewGrid}>
            <div style={styles.resultOverviewItem}>
              <div style={styles.resultOverviewNumber}>
                {activeResult.total_scenarios ?? activeMetrics?.total_scenarios ?? '—'}
              </div>
              <div style={styles.resultOverviewLabel}>Scenarios Evaluated</div>
              <div style={styles.resultOverviewSub}>
                {activeMetrics?.attack_scenarios ?? 0} attacks · {activeMetrics?.legitimate_scenarios ?? 0} benign
              </div>
            </div>

            <div style={styles.resultMetricBox}>
              <div style={styles.resultMetricLabel}>Attack Success Rate (ASR)</div>
              <div
                style={{
                  ...styles.resultMetricValue,
                  color: (activeMetrics?.attack_success_rate ?? 0) === 0 ? 'var(--tier-safe, #4ade80)' : 'var(--tier-high, #f87171)',
                }}
              >
                {activeMetrics?.attack_success_rate != null
                  ? `${(activeMetrics.attack_success_rate * 100).toFixed(1)}%`
                  : '—'}
              </div>
              <div style={styles.resultMetricHelp}>Lower is better (0.0% is optimal)</div>
            </div>

            <div style={styles.resultMetricBox}>
              <div style={styles.resultMetricLabel}>Legitimate Task Completion (LTCR)</div>
              <div
                style={{
                  ...styles.resultMetricValue,
                  color: (activeMetrics?.legitimate_task_completion_rate ?? 1) >= 0.95 ? 'var(--tier-safe, #4ade80)' : 'var(--tier-medium, #facc15)',
                }}
              >
                {activeMetrics?.legitimate_task_completion_rate != null
                  ? `${(activeMetrics.legitimate_task_completion_rate * 100).toFixed(1)}%`
                  : '—'}
              </div>
              <div style={styles.resultMetricHelp}>Higher is better (100.0% is optimal)</div>
            </div>

            <div style={styles.resultMetricBox}>
              <div style={styles.resultMetricLabel}>Median Execution Latency</div>
              <div style={styles.resultMetricValueMono}>
                {activeMetrics?.latency_median_ms != null
                  ? `${activeMetrics.latency_median_ms.toFixed(2)} ms`
                  : '—'}
              </div>
              <div style={styles.resultMetricHelp}>
                mean: {activeMetrics?.latency_mean_ms != null ? `${activeMetrics.latency_mean_ms.toFixed(1)} ms` : '—'}
              </div>
            </div>
          </div>

          {/* Category Breakdown Table */}
          {activeMetrics?.by_category && Object.keys(activeMetrics.by_category).length > 0 && (
            <div style={{ marginTop: 20 }}>
              <div style={styles.subtableHeading}>Per-Category Accuracy Breakdown</div>
              <div style={styles.tableWrap}>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.th}>Category</th>
                      <th style={styles.th}>Scenarios</th>
                      <th style={styles.th}>Correct Decisions</th>
                      <th style={styles.th}>Accuracy</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(activeMetrics.by_category).map(([cat, val]) => (
                      <tr key={cat} style={styles.tr}>
                        <td style={styles.td}><strong>{cat.replace(/_/g, ' ')}</strong></td>
                        <td style={{ ...styles.td, ...styles.mono }}>{val.total}</td>
                        <td style={{ ...styles.td, ...styles.mono }}>{val.correct}</td>
                        <td style={{ ...styles.td, ...styles.mono }}>
                          {val.accuracy != null ? `${(val.accuracy * 100).toFixed(1)}%` : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <div style={styles.latestResultFooter}>
            <a
              href={api.exportExperiment(activeResult.run_id)}
              style={styles.exportBtn}
              target="_blank"
              rel="noreferrer"
            >
              ⬇ Export Benchmark Data (CSV)
            </a>
            <span style={styles.runIdMuted}>Run ID: {activeResult.run_id}</span>
          </div>
        </div>
      )}

      {/* ── Section 5: Configuration Comparison ── */}
      <div style={styles.sectionCard}>
        <div style={styles.sectionHeaderRow}>
          <div>
            <div style={styles.sectionNumber}>SECTION 5</div>
            <div style={styles.sectionTitle}>Configuration Comparison</div>
            <div style={styles.sectionSubtitle}>
              Empirical evaluation comparison across PromptAegis governance configurations.
            </div>
          </div>
        </div>

        <div style={styles.neutralResearchBanner}>
          <span style={{ fontSize: 14 }}>ℹ️</span>
          <span>
            <strong>Research Comparison:</strong> This matrix presents measured security outcomes across configurations evaluated against the benchmark dataset. Configurations are not ranked; each isolates the contribution of specific security controls.
          </span>
        </div>

        <div style={styles.tableWrap}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Configuration</th>
                <th style={styles.th}>Attack Success Rate (ASR)</th>
                <th style={styles.th}>Legitimate Completion (LTCR)</th>
                <th style={styles.th}>Median Latency</th>
                <th style={styles.th}>Evaluated Scenarios</th>
                <th style={styles.th}>Last Evaluated</th>
              </tr>
            </thead>
            <tbody>
              {comparisonData.map((row) => (
                <tr key={row.id} style={styles.tr}>
                  <td style={styles.td}>
                    <div style={styles.tableNameCell}>
                      <span style={styles.tableLabelBold}>{row.label}</span>
                      <span style={styles.tableTagMuted}>{row.tag}</span>
                    </div>
                  </td>
                  <td style={styles.td}>
                    {row.asr != null ? (
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          color: row.asr === 0 ? 'var(--tier-safe, #4ade80)' : 'var(--tier-high, #f87171)',
                        }}
                      >
                        {(row.asr * 100).toFixed(1)}%
                      </span>
                    ) : (
                      <span style={styles.mutedPlaceholder}>Not yet evaluated</span>
                    )}
                  </td>
                  <td style={styles.td}>
                    {row.ltcr != null ? (
                      <span
                        style={{
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          color: row.ltcr >= 0.95 ? 'var(--tier-safe, #4ade80)' : 'var(--tier-medium, #facc15)',
                        }}
                      >
                        {(row.ltcr * 100).toFixed(1)}%
                      </span>
                    ) : (
                      <span style={styles.mutedPlaceholder}>—</span>
                    )}
                  </td>
                  <td style={{ ...styles.td, ...styles.mono }}>
                    {row.medianLatency != null ? `${row.medianLatency.toFixed(2)} ms` : '—'}
                  </td>
                  <td style={{ ...styles.td, ...styles.mono }}>
                    {row.totalScenarios != null ? `${row.totalScenarios} scenarios` : '—'}
                  </td>
                  <td style={{ ...styles.td, fontSize: 12, color: 'var(--text-muted)' }}>
                    {row.completedAt ? formatTimestamp(row.completedAt) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Section 6: Experiment History ── */}
      <div style={styles.sectionCard}>
        <div style={styles.sectionHeaderRow}>
          <div>
            <div style={styles.sectionNumber}>SECTION 6</div>
            <div style={styles.sectionTitle}>Experiment History</div>
            <div style={styles.sectionSubtitle}>Audit log of historical research benchmark evaluation runs.</div>
          </div>
          <div>
            <button
              style={styles.refreshBtn}
              onClick={loadHistory}
              disabled={historyLoading}
            >
              {historyLoading ? 'Refreshing…' : '↻ Refresh History'}
            </button>
          </div>
        </div>

        <div style={styles.tableWrap}>
          <table style={styles.table}>
            <thead>
              <tr>
                <th style={styles.th}>Run</th>
                <th style={styles.th}>Configuration</th>
                <th style={styles.th}>Scenarios</th>
                <th style={styles.th}>ASR</th>
                <th style={styles.th}>LTCR</th>
                <th style={styles.th}>Status</th>
                <th style={styles.th}>Started</th>
                <th style={styles.th}>Details</th>
              </tr>
            </thead>
            <tbody>
              {historyLoading && history.length === 0 ? (
                <tr>
                  <td colSpan={8} style={styles.tdCenter}>Loading benchmark history…</td>
                </tr>
              ) : history.length === 0 ? (
                <tr>
                  <td colSpan={8} style={styles.tdCenter}>
                    No benchmark experiments recorded yet. Use the controls above to execute an evaluation.
                  </td>
                </tr>
              ) : (
                history.map((run) => {
                  const m = run.metrics ?? run.results ?? {}
                  const asr = m?.asr ?? m?.attack_success_rate
                  const ltcr = m?.ltcr ?? m?.legitimate_task_completion_rate
                  const isExpanded = expandedRunId === run.run_id
                  const detail = expandedData[run.run_id]
                  const displayName = getHumanRunName(run, history)
                  const cfgObj = CONFIGURATIONS.find((c) => c.id === run.configuration)

                  return [
                    <tr
                      key={run.run_id}
                      style={{
                        ...styles.tr,
                        cursor: 'pointer',
                        background: isExpanded ? 'rgba(69, 217, 196, 0.05)' : 'transparent',
                      }}
                      onClick={() => handleToggleExpand(run.run_id)}
                    >
                      <td style={styles.td}>
                        <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>
                          {displayName}
                        </div>
                      </td>
                      <td style={styles.td}>
                        <span style={styles.configInlineBadge}>
                          {cfgObj?.label || run.configuration}
                        </span>
                      </td>
                      <td style={{ ...styles.td, ...styles.mono }}>
                        {run.total_scenarios ?? m?.total_scenarios ?? '—'}
                      </td>
                      <td style={{ ...styles.td, ...styles.mono }}>
                        {asr != null ? (
                          <span style={{ color: asr === 0 ? 'var(--tier-safe, #4ade80)' : 'var(--tier-high, #f87171)' }}>
                            {(asr * 100).toFixed(1)}%
                          </span>
                        ) : '—'}
                      </td>
                      <td style={{ ...styles.td, ...styles.mono }}>
                        {ltcr != null ? (
                          <span style={{ color: ltcr >= 0.95 ? 'var(--tier-safe, #4ade80)' : 'var(--tier-medium, #facc15)' }}>
                            {(ltcr * 100).toFixed(1)}%
                          </span>
                        ) : '—'}
                      </td>
                      <td style={styles.td}>
                        <span
                          style={{
                            ...styles.statusBadge,
                            background: run.status === 'completed' ? 'rgba(74, 222, 128, 0.12)' : 'rgba(245, 185, 66, 0.14)',
                            color: run.status === 'completed' ? 'var(--tier-safe, #4ade80)' : 'var(--tier-medium, #facc15)',
                          }}
                        >
                          {run.status || 'completed'}
                        </span>
                      </td>
                      <td style={{ ...styles.td, fontSize: 12, color: 'var(--text-muted)' }}>
                        {formatTimestamp(run.started_at)}
                      </td>
                      <td style={styles.td}>
                        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                          <button
                            style={styles.expandBtn}
                            onClick={(e) => {
                              e.stopPropagation()
                              handleToggleExpand(run.run_id)
                            }}
                          >
                            {isExpanded ? 'Hide Details ▲' : 'Inspect ▼'}
                          </button>
                        </div>
                      </td>
                    </tr>,
                    isExpanded && (
                      <tr key={`${run.run_id}-expanded`}>
                        <td colSpan={8} style={styles.expandedDrawer}>
                          <div style={styles.drawerInner}>
                            <div style={styles.drawerHeader}>
                              <div>
                                <div style={styles.drawerTitle}>{displayName}</div>
                                <div style={styles.drawerMeta}>
                                  Configuration: <strong>{cfgObj?.label || run.configuration}</strong> · Run ID: <span style={styles.monoMuted}>{run.run_id}</span>
                                </div>
                              </div>
                              <a
                                href={api.exportExperiment(run.run_id)}
                                style={styles.exportBtn}
                                target="_blank"
                                rel="noreferrer"
                              >
                                ⬇ Download CSV
                              </a>
                            </div>

                            {/* Key Metrics Grid */}
                            <div style={styles.drawerMetricsGrid}>
                              <div style={styles.drawerMetricItem}>
                                <div style={styles.drawerMetricLabel}>Scenarios Evaluated</div>
                                <div style={styles.drawerMetricVal}>{run.total_scenarios ?? m?.total_scenarios ?? '—'}</div>
                              </div>
                              <div style={styles.drawerMetricItem}>
                                <div style={styles.drawerMetricLabel}>Attack Scenarios</div>
                                <div style={styles.drawerMetricVal}>{m?.attack_scenarios ?? '—'}</div>
                              </div>
                              <div style={styles.drawerMetricItem}>
                                <div style={styles.drawerMetricLabel}>Benign Scenarios</div>
                                <div style={styles.drawerMetricVal}>{m?.legitimate_scenarios ?? '—'}</div>
                              </div>
                              <div style={styles.drawerMetricItem}>
                                <div style={styles.drawerMetricLabel}>Attack Success Rate</div>
                                <div style={{ ...styles.drawerMetricVal, color: asr === 0 ? 'var(--tier-safe, #4ade80)' : 'var(--tier-high, #f87171)' }}>
                                  {asr != null ? `${(asr * 100).toFixed(1)}%` : '—'}
                                </div>
                              </div>
                              <div style={styles.drawerMetricItem}>
                                <div style={styles.drawerMetricLabel}>Legitimate Completion</div>
                                <div style={{ ...styles.drawerMetricVal, color: ltcr >= 0.95 ? 'var(--tier-safe, #4ade80)' : 'var(--tier-medium, #facc15)' }}>
                                  {ltcr != null ? `${(ltcr * 100).toFixed(1)}%` : '—'}
                                </div>
                              </div>
                              <div style={styles.drawerMetricItem}>
                                <div style={styles.drawerMetricLabel}>Median Latency</div>
                                <div style={{ ...styles.drawerMetricVal, fontFamily: 'var(--font-mono)' }}>
                                  {m?.latency_median_ms != null ? `${m.latency_median_ms.toFixed(2)} ms` : '—'}
                                </div>
                              </div>
                            </div>

                            {/* Detailed Per-Scenario Events */}
                            {!detail ? (
                              <div style={{ padding: '16px 0', color: 'var(--text-muted)' }}>Loading event details…</div>
                            ) : detail.events && detail.events.length > 0 ? (
                              <div style={{ marginTop: 16 }}>
                                <div style={styles.subtableHeading}>Per-Scenario Execution Outcomes ({detail.events.length} scenarios)</div>
                                <div style={{ ...styles.tableWrap, maxHeight: 300, overflowY: 'auto' }}>
                                  <table style={styles.table}>
                                    <thead>
                                      <tr>
                                        <th style={styles.th}>Scenario ID</th>
                                        <th style={styles.th}>Category</th>
                                        <th style={styles.th}>Expected</th>
                                        <th style={styles.th}>Actual</th>
                                        <th style={styles.th}>Outcome</th>
                                        <th style={styles.th}>Latency</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {detail.events.slice(0, 100).map((evt) => (
                                        <tr key={evt.event_id || evt.scenario_id} style={styles.tr}>
                                          <td style={{ ...styles.td, ...styles.mono, fontSize: 11.5 }}>{evt.scenario_id}</td>
                                          <td style={styles.td}>{evt.category?.replace(/_/g, ' ')}</td>
                                          <td style={{ ...styles.td, ...styles.mono }}>{evt.expected_decision}</td>
                                          <td style={{ ...styles.td, ...styles.mono }}>{evt.actual_decision}</td>
                                          <td style={styles.td}>
                                            <span
                                              style={{
                                                ...styles.statusBadge,
                                                background: evt.correct ? 'rgba(74, 222, 128, 0.12)' : 'rgba(239, 68, 68, 0.14)',
                                                color: evt.correct ? 'var(--tier-safe, #4ade80)' : 'var(--tier-high, #f87171)',
                                              }}
                                            >
                                              {evt.correct ? 'CORRECT' : 'INCORRECT'}
                                            </span>
                                          </td>
                                          <td style={{ ...styles.td, ...styles.mono }}>
                                            {evt.latency_ms != null ? `${evt.latency_ms.toFixed(1)} ms` : '—'}
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                                {detail.events.length > 100 && (
                                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginTop: 8 }}>
                                    Showing first 100 of {detail.events.length} events. Download CSV for the complete raw audit dataset.
                                  </div>
                                )}
                              </div>
                            ) : null}
                          </div>
                        </td>
                      </tr>
                    ),
                  ]
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ─── Styles ────────────────────────────────────────────────────────────────

const styles = {
  container: {
    maxWidth: 1280,
    margin: '0 auto',
    paddingBottom: 40,
  },
  explainerCard: {
    background: 'linear-gradient(180deg, rgba(69, 217, 196, 0.08) 0%, rgba(20, 27, 36, 0.6) 100%)',
    border: '1px solid rgba(69, 217, 196, 0.3)',
    borderRadius: 10,
    padding: '18px 22px',
    marginBottom: 24,
  },
  explainerHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    marginBottom: 8,
  },
  explainerIcon: {
    fontSize: 18,
  },
  explainerTitle: {
    fontSize: 15,
    fontWeight: 700,
    color: 'var(--signal, #45D9C4)',
    letterSpacing: '0.02em',
  },
  explainerBody: {
    fontSize: 13.5,
    lineHeight: 1.6,
    color: 'var(--text-primary)',
    margin: 0,
    marginBottom: 14,
  },
  metricDefinitionRow: {
    display: 'flex',
    gap: 16,
    flexWrap: 'wrap',
    borderTop: '1px solid rgba(255, 255, 255, 0.08)',
    paddingTop: 12,
  },
  definitionPill: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    fontSize: 12.5,
    color: 'var(--text-muted)',
  },
  defBadgeRed: {
    fontSize: 11,
    fontWeight: 700,
    fontFamily: 'var(--font-mono)',
    background: 'rgba(239, 68, 68, 0.15)',
    color: 'var(--tier-high, #f87171)',
    padding: '2px 8px',
    borderRadius: 4,
  },
  defBadgeGreen: {
    fontSize: 11,
    fontWeight: 700,
    fontFamily: 'var(--font-mono)',
    background: 'rgba(74, 222, 128, 0.15)',
    color: 'var(--tier-safe, #4ade80)',
    padding: '2px 8px',
    borderRadius: 4,
  },
  defText: {
    fontSize: 12,
  },
  sectionCard: {
    background: 'var(--surface, #141B24)',
    border: '1px solid var(--border, #232E3B)',
    borderRadius: 10,
    padding: 22,
    marginBottom: 24,
  },
  sectionHeaderRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 18,
    gap: 16,
    flexWrap: 'wrap',
  },
  sectionNumber: {
    fontSize: 10.5,
    fontWeight: 800,
    fontFamily: 'var(--font-mono)',
    color: 'var(--signal, #45D9C4)',
    letterSpacing: '0.08em',
    marginBottom: 2,
  },
  sectionTitle: {
    fontSize: 17,
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  sectionSubtitle: {
    fontSize: 12.5,
    color: 'var(--text-muted)',
    marginTop: 4,
  },
  helperCallout: {
    display: 'flex',
    alignItems: 'center',
    background: 'rgba(255, 255, 255, 0.04)',
    border: '1px solid var(--border)',
    borderRadius: 6,
    padding: '6px 12px',
    fontSize: 12,
    color: 'var(--text-muted)',
    maxWidth: 500,
  },
  configGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
    gap: 14,
  },
  configCard: {
    background: 'var(--bg, #0D1117)',
    border: '1px solid var(--border, #232E3B)',
    borderRadius: 8,
    padding: 16,
    cursor: 'pointer',
    transition: 'all 0.18s ease',
  },
  configCardSelected: {
    borderColor: 'var(--signal, #45D9C4)',
    background: 'rgba(69, 217, 196, 0.06)',
    boxShadow: '0 0 12px rgba(69, 217, 196, 0.15)',
  },
  configCardTop: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 10,
  },
  configRadio: {
    display: 'flex',
    alignItems: 'center',
  },
  configTag: {
    fontSize: 10,
    fontWeight: 700,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    padding: '2px 6px',
    borderRadius: 3,
    background: 'rgba(255, 255, 255, 0.06)',
    color: 'var(--text-muted)',
  },
  configHeading: {
    fontSize: 14,
    fontWeight: 800,
    letterSpacing: '0.02em',
    color: 'var(--text-primary)',
    marginBottom: 6,
  },
  configDesc: {
    fontSize: 12,
    fontWeight: 600,
    color: 'var(--signal, #45D9C4)',
    marginBottom: 8,
    lineHeight: 1.4,
  },
  configDetails: {
    fontSize: 11.5,
    color: 'var(--text-muted)',
    lineHeight: 1.5,
  },
  textActionBtn: {
    background: 'transparent',
    border: '1px solid var(--border)',
    borderRadius: 6,
    color: 'var(--signal, #45D9C4)',
    padding: '6px 12px',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  categoryGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
    gap: 12,
    marginBottom: 18,
  },
  categoryCard: {
    display: 'block',
    background: 'var(--bg, #0D1117)',
    border: '1px solid var(--border, #232E3B)',
    borderRadius: 8,
    padding: '12px 14px',
    cursor: 'pointer',
    transition: 'border-color 0.15s ease',
  },
  categoryCardChecked: {
    borderColor: 'rgba(69, 217, 196, 0.4)',
  },
  categoryCardTop: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  categoryTypeBadge: {
    fontSize: 10,
    fontWeight: 700,
    padding: '2px 6px',
    borderRadius: 3,
    textTransform: 'uppercase',
  },
  categoryName: {
    fontSize: 13,
    fontWeight: 700,
    color: 'var(--text-primary)',
    marginBottom: 4,
  },
  categoryDesc: {
    fontSize: 11.5,
    color: 'var(--text-muted)',
    lineHeight: 1.4,
  },
  sampleSelectorBox: {
    background: 'rgba(255, 255, 255, 0.02)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    padding: '12px 16px',
  },
  sampleLabel: {
    fontSize: 12,
    fontWeight: 700,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
    marginBottom: 10,
  },
  sampleOptionsRow: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: 18,
    alignItems: 'center',
  },
  sampleRadioLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    fontSize: 12.5,
    cursor: 'pointer',
    color: 'var(--text-primary)',
  },
  customCountInput: {
    width: 90,
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 4,
    color: 'var(--text-primary)',
    padding: '4px 8px',
    fontSize: 12,
    fontFamily: 'var(--font-mono)',
  },
  runActionBox: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 20,
    flexWrap: 'wrap',
  },
  primaryRunBtn: {
    background: 'var(--signal, #45D9C4)',
    color: '#04211D',
    border: 'none',
    borderRadius: 6,
    padding: '12px 28px',
    fontSize: 14,
    fontWeight: 800,
    cursor: 'pointer',
    transition: 'opacity 0.15s ease',
  },
  primaryRunBtnDisabled: {
    opacity: 0.6,
    cursor: 'not-allowed',
  },
  runningFlex: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
  },
  spinner: {
    display: 'inline-block',
    animation: 'spin 1s linear infinite',
  },
  runSupportText: {
    fontSize: 12.5,
    color: 'var(--text-muted)',
    marginTop: 8,
    maxWidth: 550,
    lineHeight: 1.5,
  },
  runConfigSummaryPill: {
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    padding: '10px 16px',
    textAlign: 'right',
  },
  runSummaryHeading: {
    fontSize: 10.5,
    textTransform: 'uppercase',
    color: 'var(--text-muted)',
    fontWeight: 700,
    letterSpacing: '0.04em',
  },
  runSummaryValue: {
    fontSize: 14,
    fontWeight: 800,
    color: 'var(--signal, #45D9C4)',
    marginTop: 2,
  },
  runSummaryCategories: {
    fontSize: 11.5,
    color: 'var(--text-muted)',
    marginTop: 2,
  },
  errorBanner: {
    marginTop: 14,
    padding: '10px 14px',
    background: 'rgba(239, 68, 68, 0.12)',
    border: '1px solid rgba(239, 68, 68, 0.4)',
    borderRadius: 6,
    color: 'var(--tier-high, #f87171)',
    fontSize: 13,
    display: 'flex',
    alignItems: 'center',
    gap: 8,
  },
  latestResultCard: {
    background: 'linear-gradient(180deg, rgba(69, 217, 196, 0.05) 0%, var(--surface, #141B24) 100%)',
    border: '1px solid rgba(69, 217, 196, 0.4)',
    borderRadius: 10,
    padding: 22,
    marginBottom: 24,
  },
  latestResultHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 18,
  },
  latestResultEyebrow: {
    fontSize: 10.5,
    fontWeight: 800,
    fontFamily: 'var(--font-mono)',
    color: 'var(--signal, #45D9C4)',
    letterSpacing: '0.08em',
  },
  latestResultTitle: {
    fontSize: 18,
    fontWeight: 800,
    color: 'var(--text-primary)',
    marginTop: 2,
  },
  latestResultConfigBadge: {
    background: 'rgba(69, 217, 196, 0.15)',
    border: '1px solid rgba(69, 217, 196, 0.3)',
    color: 'var(--signal, #45D9C4)',
    padding: '4px 10px',
    borderRadius: 4,
    fontSize: 12,
    fontWeight: 700,
  },
  resultOverviewGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: 14,
  },
  resultOverviewItem: {
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    padding: '16px 18px',
    textAlign: 'center',
  },
  resultOverviewNumber: {
    fontSize: 28,
    fontWeight: 800,
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)',
  },
  resultOverviewLabel: {
    fontSize: 13,
    fontWeight: 700,
    marginTop: 4,
    color: 'var(--text-primary)',
  },
  resultOverviewSub: {
    fontSize: 11.5,
    color: 'var(--text-muted)',
    marginTop: 4,
  },
  resultMetricBox: {
    background: 'var(--bg)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    padding: '16px 18px',
    textAlign: 'center',
  },
  resultMetricLabel: {
    fontSize: 12,
    fontWeight: 600,
    color: 'var(--text-muted)',
    marginBottom: 4,
  },
  resultMetricValue: {
    fontSize: 26,
    fontWeight: 800,
    fontFamily: 'var(--font-mono)',
  },
  resultMetricValueMono: {
    fontSize: 24,
    fontWeight: 800,
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)',
  },
  resultMetricHelp: {
    fontSize: 11,
    color: 'var(--text-muted)',
    marginTop: 4,
  },
  subtableHeading: {
    fontSize: 13,
    fontWeight: 700,
    color: 'var(--text-primary)',
    marginBottom: 8,
  },
  latestResultFooter: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 20,
    paddingTop: 16,
    borderTop: '1px solid var(--border)',
  },
  exportBtn: {
    background: 'transparent',
    border: '1px solid var(--signal, #45D9C4)',
    color: 'var(--signal, #45D9C4)',
    borderRadius: 6,
    padding: '6px 14px',
    fontSize: 12.5,
    fontWeight: 700,
    textDecoration: 'none',
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
  },
  runIdMuted: {
    fontSize: 11.5,
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-muted)',
  },
  neutralResearchBanner: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    background: 'rgba(255, 255, 255, 0.03)',
    border: '1px solid var(--border)',
    borderRadius: 6,
    padding: '10px 14px',
    fontSize: 12.5,
    color: 'var(--text-muted)',
    marginBottom: 16,
    lineHeight: 1.5,
  },
  tableWrap: {
    overflowX: 'auto',
  },
  table: {
    width: '100%',
    borderCollapse: 'collapse',
    fontSize: 13,
  },
  th: {
    textAlign: 'left',
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    fontWeight: 700,
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    padding: '10px 12px',
    borderBottom: '1px solid var(--border)',
    background: 'rgba(0, 0, 0, 0.1)',
  },
  td: {
    padding: '12px',
    verticalAlign: 'middle',
  },
  tr: {
    borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
  },
  tableNameCell: {
    display: 'flex',
    flexDirection: 'column',
    gap: 2,
  },
  tableLabelBold: {
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  tableTagMuted: {
    fontSize: 11,
    color: 'var(--text-muted)',
  },
  mutedPlaceholder: {
    color: 'var(--text-muted)',
    fontSize: 12,
  },
  refreshBtn: {
    background: 'transparent',
    border: '1px solid var(--border)',
    color: 'var(--text-primary)',
    borderRadius: 6,
    padding: '6px 12px',
    fontSize: 12,
    fontWeight: 600,
    cursor: 'pointer',
  },
  tdCenter: {
    padding: 24,
    textAlign: 'center',
    color: 'var(--text-muted)',
    fontSize: 13,
  },
  configInlineBadge: {
    fontSize: 11,
    fontWeight: 700,
    fontFamily: 'var(--font-mono)',
    background: 'rgba(255, 255, 255, 0.05)',
    padding: '3px 8px',
    borderRadius: 4,
    color: 'var(--text-primary)',
  },
  statusBadge: {
    fontSize: 10.5,
    fontWeight: 700,
    fontFamily: 'var(--font-mono)',
    padding: '3px 8px',
    borderRadius: 4,
    textTransform: 'uppercase',
  },
  expandBtn: {
    background: 'transparent',
    border: '1px solid var(--border)',
    color: 'var(--signal, #45D9C4)',
    borderRadius: 4,
    padding: '3px 8px',
    fontSize: 11,
    fontWeight: 600,
    cursor: 'pointer',
  },
  expandedDrawer: {
    padding: 0,
    background: 'rgba(10, 15, 20, 0.95)',
    borderBottom: '1px solid var(--border)',
  },
  drawerInner: {
    padding: 20,
    borderLeft: '3px solid var(--signal, #45D9C4)',
  },
  drawerHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 16,
  },
  drawerTitle: {
    fontSize: 15,
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  drawerMeta: {
    fontSize: 12,
    color: 'var(--text-muted)',
    marginTop: 2,
  },
  monoMuted: {
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-muted)',
  },
  drawerMetricsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
    gap: 12,
    marginBottom: 16,
  },
  drawerMetricItem: {
    background: 'rgba(255, 255, 255, 0.03)',
    border: '1px solid rgba(255, 255, 255, 0.08)',
    borderRadius: 6,
    padding: '10px 12px',
  },
  drawerMetricLabel: {
    fontSize: 11,
    color: 'var(--text-muted)',
    marginBottom: 4,
  },
  drawerMetricVal: {
    fontSize: 16,
    fontWeight: 700,
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)',
  },
  mono: {
    fontFamily: 'var(--font-mono)',
  },
}
