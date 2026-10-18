const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

/**
 * Mask API credential for presentation: never expose raw secrets in UI, logs, or exports.
 * Output format: pa_••••••••••<last4>
 */
export function maskCredential(token) {
  if (!token || typeof token !== 'string') return 'None (Unauthenticated)'
  const trimmed = token.trim()
  if (trimmed.length <= 4) return 'pa_••••••••••'
  const fragment = trimmed.slice(-4)
  return `pa_••••••••••${fragment}`
}

function getStoredToken(envId) {
  if (typeof window === 'undefined') return ''
  try {
    const stored = window.sessionStorage?.getItem(`pa_token_${envId}`)
    if (stored) return stored
  } catch {
    // sessionStorage not accessible
  }
  if (window.__PROMPTAEGIS_DEV_TOKENS__ && window.__PROMPTAEGIS_DEV_TOKENS__[envId]) {
    return window.__PROMPTAEGIS_DEV_TOKENS__[envId]
  }
  // Local development fallback — dead-code eliminated in production builds (import.meta.env.DEV === false)
  if (import.meta.env.DEV) {
    const devMap = {
      research_benchmark: 'pa_benchmark_test_key',
      local_dev: 'pa_local_dev_key',
      connected_application: 'pa_live_connected_app_key',
    }
    return devMap[envId] || ''
  }
  return ''
}

// In-memory credential and environment session store
let currentEnvironment = 'research_benchmark'
const sessionTokens = {
  research_benchmark: getStoredToken('research_benchmark'),
  local_dev: getStoredToken('local_dev'),
  connected_application: getStoredToken('connected_application'),
}

export const DEFAULT_ENV_TOKENS = {
  get research_benchmark() { return getStoredToken('research_benchmark') },
  get local_dev() { return getStoredToken('local_dev') },
  get connected_application() { return getStoredToken('connected_application') },
}

const listeners = new Set()

function notifyListeners() {
  const state = {
    environment: currentEnvironment,
    token: sessionTokens[currentEnvironment] || '',
  }
  listeners.forEach((fn) => {
    try {
      fn(state)
    } catch (e) {
      console.error('Error in environment listener', e)
    }
  })
}

async function request(path, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  }

  // Attach environment credential unless explicitly skipped (e.g. for unauthenticated testing)
  const token = options.token !== undefined ? options.token : sessionTokens[currentEnvironment]
  if (token && !options.skipAuth) {
    headers['X-PromptAegis-Key'] = token
    headers['Authorization'] = `Bearer ${token}`
  }

  // Authoritative environment header
  const envHeader = options.environment !== undefined ? options.environment : currentEnvironment
  if (envHeader && !options.skipEnvHeader) {
    headers['X-PromptAegis-Environment'] = envHeader
  }

  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers,
  })

  if (!res.ok) {
    let errorDetail = ''
    try {
      const errJson = await res.json()
      errorDetail = errJson.detail || JSON.stringify(errJson)
    } catch {
      errorDetail = await res.text().catch(() => '')
    }
    const err = new Error(errorDetail || `${res.status} ${res.statusText}`)
    err.status = res.status
    err.statusText = res.statusText
    err.detail = errorDetail
    throw err
  }

  // If 204 or empty body
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  // ---- Environment & Authentication Context Management ----
  getEnvironment: () => currentEnvironment,
  getToken: () => sessionTokens[currentEnvironment] || '',
  maskCredential,
  setEnvironment: (envId, customToken = null) => {
    currentEnvironment = envId
    if (customToken !== null) {
      sessionTokens[envId] = customToken
    } else if (!sessionTokens[envId]) {
      sessionTokens[envId] = getStoredToken(envId)
    }
    notifyListeners()
    return currentEnvironment
  },
  setTokenForEnvironment: (envId, token) => {
    sessionTokens[envId] = token
    try {
      if (typeof window !== 'undefined' && window.sessionStorage) {
        if (token) {
          window.sessionStorage.setItem(`pa_token_${envId}`, token)
        } else {
          window.sessionStorage.removeItem(`pa_token_${envId}`)
        }
      }
    } catch {}
    notifyListeners()
  },
  resetTokenForEnvironment: (envId) => {
    try {
      if (typeof window !== 'undefined' && window.sessionStorage) {
        window.sessionStorage.removeItem(`pa_token_${envId}`)
      }
    } catch {}
    sessionTokens[envId] = getStoredToken(envId)
    notifyListeners()
  },
  onEnvironmentChange: (callback) => {
    listeners.add(callback)
    return () => listeners.delete(callback)
  },

  // Environments API
  listEnvironments: () => request('/environments', { skipAuth: true, skipEnvHeader: true }),
  getCurrentEnvironmentContext: (overrideOpts = {}) => request('/environments/current', overrideOpts),
  registerEnvironment: (id, name, type, description = '') =>
    request('/environments', {
      method: 'POST',
      body: JSON.stringify({ id, name, type, description }),
    }),
  createCredential: (environmentId, name, allowedRoles = ['application_gateway']) =>
    request('/governance/credentials', {
      method: 'POST',
      body: JSON.stringify({
        environment_id: environmentId,
        name,
        allowed_roles: allowedRoles,
      }),
    }),

  // ---- Original Detection API ----
  chat: (prompt, sessionId, history = []) =>
    request('/chat', {
      method: 'POST',
      body: JSON.stringify({ prompt, session_id: sessionId, history }),
    }),

  directChat: (prompt, sessionId, history = []) =>
    request('/chat/direct', {
      method: 'POST',
      body: JSON.stringify({ prompt, session_id: sessionId, history }),
    }),

  detect: (prompt, sessionId = null, source = 'user_message') =>
    request('/detect', {
      method: 'POST',
      body: JSON.stringify({ prompt, session_id: sessionId, source }),
    }),

  simulate: (sessionId, turns) =>
    request('/simulate', {
      method: 'POST',
      body: JSON.stringify({ session_id: sessionId, turns }),
    }),

  getLogs: (tier = null, limit = 200) => {
    const params = new URLSearchParams({ limit })
    if (tier) params.set('tier', tier)
    return request(`/logs?${params.toString()}`)
  },

  clearLogs: () => request('/logs', { method: 'DELETE' }),

  getStatistics: () => request('/statistics'),

  runStressTest: () => request('/stress-test'),

  // ---- Governance API (Prompt Aegis Reference Monitor) ----

  // Principals / Agents (FR-01)
  listAgents: () => request('/agents'),
  createAgent: (name, description = '', role = 'default') =>
    request('/agents', {
      method: 'POST',
      body: JSON.stringify({ name, description, role }),
    }),
  deleteAgent: (agentId) => request(`/agents/${agentId}`, { method: 'DELETE' }),

  // Capabilities / Tools (FR-02)
  listTools: () => request('/tools'),
  createTool: (name, category, risk_level, requires_approval = false, description = '') =>
    request('/tools', {
      method: 'POST',
      body: JSON.stringify({ name, category, risk_level, requires_approval, description }),
    }),
  deleteTool: (toolId) => request(`/tools/${toolId}`, { method: 'DELETE' }),

  // Permissions / Access Boundary (FR-03)
  getPermissions: (agentId) => request(`/permissions/${agentId}`),
  setPermission: (agentId, toolId, allowed) =>
    request('/permissions', {
      method: 'POST',
      body: JSON.stringify({ agent_id: agentId, tool_id: toolId, allowed }),
    }),

  // Invariants / Parameter Policies (FR-04)
  listPolicies: (enabledOnly = false) => {
    const params = new URLSearchParams({ enabled_only: enabledOnly })
    return request(`/policies?${params.toString()}`)
  },
  createPolicy: (body) => request('/policies', { method: 'POST', body: JSON.stringify(body) }),
  togglePolicy: (policyId, enabled) =>
    request(`/policies/${policyId}`, { method: 'PATCH', body: JSON.stringify({ enabled }) }),
  deletePolicy: (policyId) => request(`/policies/${policyId}`, { method: 'DELETE' }),

  // Runtime Tool Interception (FR-05/06/07)
  intercept: (agentId, toolName, args = {}, config = 'full', source = 'runtime', context = {}) =>
    request('/intercept', {
      method: 'POST',
      body: JSON.stringify({
        agent_id: agentId,
        tool_name: toolName,
        arguments: args,
        configuration: config,
        source: source,
        context: context,
      }),
    }),

  // Structured Audit Log (FR-08)
  getToolCalls: (agentId = null, decision = null, limit = 200) => {
    const params = new URLSearchParams({ limit })
    if (agentId) params.set('agent_id', agentId)
    if (decision) params.set('decision', decision)
    return request(`/tool-calls?${params.toString()}`)
  },

  // Governance Stats
  getGovernanceStats: () => request('/governance/stats'),

  // Seed defaults (Benchmark ONLY)
  seedDefaults: () => request('/governance/seed', { method: 'POST' }),

  // Rate Limits (FR-09)
  setRateLimit: (toolName, limit) =>
    request(`/rate-limits/${encodeURIComponent(toolName)}`, {
      method: 'POST',
      body: JSON.stringify({ limit: Number(limit) }),
    }),

  // Experiments (FR-10/11/12/13)
  runExperiment: (configuration, description = '', categories = [], maxScenarios = 0) =>
    request('/experiments/run', {
      method: 'POST',
      body: JSON.stringify({
        configuration,
        description,
        scenario_categories: categories,
        max_scenarios: maxScenarios,
      }),
    }),
  listExperiments: () => request('/experiments'),
  getExperiment: (runId) => request(`/experiments/${runId}`),
  exportExperiment: (runId) => `${BASE_URL}/experiments/${runId}/export`,

  // Raw request escape hatch for negative tests / boundary validation
  rawRequest: request,
}
