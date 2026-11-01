/**
 * Host half of the egress audit.
 *
 * What it does: watches outbound traffic leaving this Host process, classifies
 * every destination, and serves one read-only JSON snapshot on its own route.
 *
 * Two observation layers:
 *  1. semantic — globalThis.fetch / undici, tool calls, model streams;
 *  2. socket fallback — net.Socket#connect, which also covers code that grabs
 *     undici's own `fetch` (the web_fetch tool does exactly that) and any other
 *     TCP client in this process.
 *
 * Safety contract (deliberate, keep it that way):
 * - never throws into a caller; every observation is wrapped in try/catch;
 * - makes no network requests of its own;
 * - keeps everything in memory, writes nothing to disk;
 * - stores no request/response bodies and no credential headers;
 * - only reads; it never rewrites, blocks, retries or delays traffic.
 */

export const name = 'dsh-egress-audit'
// The snapshot is served over the Host web server; a headless install without
// one has nowhere to serve it, so the plugin stays inactive there.
export const inject = ['webServer']

const ROUTE = '/dsh-egress/snapshot.json'
const MAX_EVENTS = 400
const MAX_AGE_MS = 60 * 60 * 1000
const LLM_WINDOW_MS = 8000
const STALL_MS = 10 * 60 * 1000
const PATCHED = Symbol.for('dsh.egress.audit.fetch')
const NET_PATCHED = Symbol.for('dsh.egress.audit.net')

/** Hosts that belong to this product's own vendor, matched exactly. */
const OFFICIAL = new Set([
  'api.deepseek.com',
  'chat.deepseek.com',
  'platform.deepseek.com',
  'www.deepseek.com',
  'deepseek.com',
  'open.deepseek.com',
  'dsh-otel-collector.deepseeksvc.com',
])

const DATA_RANK = { '对话内容': 3, '元数据': 2, '未知': 1 }

const state = {
  events: [],
  seq: 0,
  startedAt: Date.now(),
  lastSeenAt: 0,
  tag: null,
  watching: false,
  sockets: false,
}

/**
 * Marks the async context of a request the fetch layer already recorded, so the
 * socket fallback does not report the same connection twice.
 */
function createStore() {
  try {
    const mod = process.getBuiltinModule('node:async_hooks')
    return new mod.AsyncLocalStorage()
  } catch {
    return null
  }
}

const store = createStore()

function parseUrl(url) {
  try {
    const parsed = new URL(String(url))
    return {
      host: parsed.host.toLowerCase(),
      hostname: parsed.hostname.toLowerCase(),
      protocol: parsed.protocol.toLowerCase(),
      port: parsed.port,
    }
  } catch {
    return { host: '', hostname: '', protocol: '', port: '' }
  }
}

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]', '0.0.0.0'])

/** Registrable families this product ships with; used to spot name-carrying. */
const OFFICIAL_FAMILIES = ['deepseek.com', 'deepseeksvc.com']

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/
const LAN = /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/
const STRENGTH_RANK = { strong: 3, medium: 2, weak: 1, info: 0 }

/** Levenshtein distance, bounded: anything farther than `limit` is useless here. */
function distance(a, b, limit) {
  if (Math.abs(a.length - b.length) > limit) return limit + 1
  let prev = new Array(b.length + 1)
  let cur = new Array(b.length + 1)
  for (let j = 0; j <= b.length; j += 1) prev[j] = j
  for (let i = 1; i <= a.length; i += 1) {
    cur[0] = i
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
    }
    const swap = prev
    prev = cur
    cur = swap
  }
  return prev[b.length]
}

/**
 * Objective classification for one destination. Every returned mark carries the
 * rule that fired and the evidence behind it: the panel shows the reason, never
 * a bare "suspicious" that the user cannot audit.
 */
function assess(parsed) {
  const hostname = parsed.hostname
  const marks = []
  const add = (rule, label, detail, strength) => {
    marks.push({ rule, label, detail, strength })
  }

  if (!hostname) {
    add('no-host', '没有主机名', '请求地址里没有可识别的主机，无法判断归属', 'medium')
    return { tier: 'unknown', marks }
  }
  if (LOOPBACK.has(hostname)) {
    add('loopback', '本机地址', '数据没有离开这台电脑，通常本地中继或代理', 'info')
    return { tier: 'local', marks }
  }
  if (OFFICIAL.has(hostname)) {
    add('official', '官方域名', '主机名与官方名单精确相等，不做后缀模糊匹配', 'info')
    return { tier: 'official', marks }
  }

  const bare = hostname.replace(/^www\./, '')

  if (/^xn--/.test(hostname) || /[^\x00-\x7f]/.test(hostname)) {
    add('idn', '形近字域名', '主机名含 punycode（xn--）或非 ASCII 字符，可能用形近字冒充官方域名', 'strong')
  }

  const family = OFFICIAL_FAMILIES.find((item) => bare.includes(item))
  if (family) {
    add('carries-official', '夹带官方名', `主机名包含 ${family}，但它不是官方域名本身`, 'strong')
  } else if (bare.includes('deepseek')) {
    add('carries-brand', '夹带品牌名', '主机名含 deepseek 但不属于任何官方域名', 'strong')
  } else {
    for (const official of OFFICIAL) {
      if (distance(bare, official, 2) <= 2) {
        add('lookalike', '形近官方域名', `与官方域名 ${official} 只差一两个字符`, 'strong')
        break
      }
    }
  }

  if (IPV4.test(hostname)) {
    if (LAN.test(hostname)) {
      add('lan', '局域网地址', '发往局域网内的设备，数据离开了这台电脑', 'medium')
    } else {
      add('ip-literal', '直接用 IP', '没有域名，无法从域名或证书判断归属', 'medium')
    }
  }

  if (parsed.protocol === 'http:') {
    add('cleartext', '明文传输', '用 http 发送，链路上任何一环都能读到内容', 'medium')
  }

  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    add('odd-port', '非常规端口', `使用端口 ${parsed.port}，不是 80/443`, 'weak')
  }

  const strong = marks.some((mark) => mark.strength === 'strong')
  return { tier: strong ? 'suspicious' : 'external', marks }
}

function bodySize(init) {
  if (!init || init.body == null) return 0
  const body = init.body
  if (typeof body === 'string') return body.length
  if (typeof body === 'object' && typeof body.byteLength === 'number') return body.byteLength
  return 0
}

function trimUrl(url) {
  const text = String(url)
  return text.length > 160 ? `${text.slice(0, 157)}...` : text
}

function defaultData(hostname) {
  return hostname === 'dsh-otel-collector.deepseeksvc.com' ? '元数据' : '未知'
}

/** Our own package plus transport libraries: attribution should name the caller. */
const SKIP_PACKAGES = new Set([name, 'undici', 'node-fetch', 'follow-redirects'])

/** Walks the stack and returns the first package directory that is not us. */
function callerPackage() {
  const stack = new Error().stack
  if (!stack) return 'unknown'
  for (const line of stack.split('\n').slice(1)) {
    const match = /[\\/]node_modules[\\/]((?:@[^\\/]+[\\/])?[^\\/]+)[\\/]/.exec(line)
    if (!match) continue
    const pkg = match[1].replace(/\\/g, '/')
    if (SKIP_PACKAGES.has(pkg)) continue
    return pkg
  }
  return 'unknown'
}

function record(event) {
  try {
    state.events.push(event)
    if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS)
    state.lastSeenAt = event.at
  } catch {
    /* observation never breaks a caller */
  }
}

function activeTag() {
  return state.tag && state.tag.until > Date.now() ? state.tag : null
}

function makeEvent({ url, method, by, size, channel, data }) {
  const parsed = parseUrl(url)
  const tag = activeTag()
  const verdict = assess(parsed)
  let value = defaultData(parsed.hostname)
  if (data) value = data
  else if (tag) value = size >= 2000 || channel === 'tcp' ? tag.data : '元数据'
  return {
    id: ++state.seq,
    at: Date.now(),
    channel: channel || (tag ? tag.channel : 'http'),
    method: method || 'GET',
    host: parsed.host,
    url: trimUrl(url),
    by: by || 'unknown',
    tier: verdict.tier,
    marks: verdict.marks.map((mark) => ({
      rule: mark.rule,
      label: mark.label,
      detail: mark.detail,
      strength: mark.strength,
    })),
    data: value,
    model: tag && tag.model ? tag.model : '',
    outcome: 'attempted',
    status: 0,
    error: '',
  }
}

/**
 * Wraps the Host's global fetch. The wrapper returns the original Response
 * untouched (so streaming, bodies and identity all keep working) and only
 * annotates its own record with the status observed at resolution time.
 */
function installFetch() {
  const target = globalThis
  const original = target.fetch
  if (typeof original !== 'function') return () => {}
  if (original[PATCHED]) return () => {}

  const wrapped = function fetch(input, init) {
    let event = null
    try {
      const url = typeof input === 'string'
        ? input
        : input && typeof input.url === 'string' ? input.url : String(input)
      const method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase()
      event = makeEvent({ url, method, by: callerPackage(), size: bodySize(init) })
    } catch {
      event = null
    }
    if (event) record(event)

    const mark = () => {
      const pending = store
        ? store.run({ seen: true }, () => original.call(this, input, init))
        : original.call(this, input, init)
      return pending
    }
    if (!event) return mark()

    return mark().then((response) => {
      try {
        event.status = response.status
        event.outcome = response.ok ? 'sent' : 'failed'
        if (!response.ok) event.error = `HTTP ${response.status}`
        const length = response.headers.get('content-length')
        if (length && Number.isFinite(Number(length))) event.bytes = Number(length)
      } catch {
        /* annotation only */
      }
      return response
    }, (error) => {
      try {
        event.outcome = 'failed'
        event.error = String((error && error.message) || error)
      } catch {
        /* annotation only */
      }
      throw error
    })
  }

  wrapped[PATCHED] = true
  target.fetch = wrapped
  state.watching = true

  return () => {
    if (target.fetch === wrapped) {
      target.fetch = original
      state.watching = false
    }
  }
}

/** Turns the many shapes of Socket#connect arguments into one address. */
function netTarget(args) {
  let first = args[0]
  // Node passes an already-normalized [options, cb, symbol] array on its
  // internal paths, which is how undici reaches this method.
  if (Array.isArray(first)) first = first[0]
  let host = ''
  let port = 0
  if (first && typeof first === 'object') {
    if (first.path) return null
    host = String(first.host || first.hostname || first.servername || '')
    port = Number(first.port) || 0
  } else if (typeof first === 'number') {
    port = first
    if (typeof args[1] === 'string') host = args[1]
  } else {
    return null
  }
  if (!host || !port) return null
  const bare = host.replace(/^\[|\]$/g, '').toLowerCase()
  const url = port === 443
    ? `https://${bare}/`
    : port === 80
      ? `http://${bare}/`
      : `tcp://${bare}:${port}/`
  return { url, host: bare, port }
}

/**
 * Fallback layer: anything that opens a TCP connection from this process, which
 * includes code that imports undici's own fetch (the built-in web_fetch tool)
 * and never touches globalThis.fetch.
 */
function installNet() {
  let net
  try {
    net = process.getBuiltinModule('node:net')
  } catch {
    return () => {}
  }
  const proto = net && net.Socket && net.Socket.prototype
  if (!proto || typeof proto.connect !== 'function') return () => {}
  const original = proto.connect
  if (original[NET_PATCHED]) return () => {}

  const wrapped = function connect(...args) {
    let event = null
    try {
      const seen = store && store.getStore() ? store.getStore().seen : false
      const target = seen ? null : netTarget(args)
      if (target) {
        event = makeEvent({
          url: target.url,
          method: 'CONNECT',
          by: callerPackage(),
          size: 0,
          channel: 'tcp',
        })
      }
    } catch {
      event = null
    }
    if (!event) return original.apply(this, args)
    record(event)

    let socket
    try {
      socket = original.apply(this, args)
    } catch (error) {
      event.outcome = 'failed'
      event.error = String((error && error.message) || error)
      throw error
    }
    try {
      socket.once('connect', () => {
        if (event.outcome === 'attempted') event.outcome = 'sent'
      })
      socket.once('error', (error) => {
        event.outcome = 'failed'
        event.error = String((error && (error.code || error.message)) || error)
      })
    } catch {
      /* annotation only */
    }
    return socket
  }

  wrapped[NET_PATCHED] = true
  proto.connect = wrapped
  state.sockets = true

  return () => {
    if (proto.connect === wrapped) {
      proto.connect = original
      state.sockets = false
    }
  }
}

function extractUrl(args) {
  if (!args || typeof args !== 'object') return ''
  for (const key of ['url', 'uri', 'endpoint', 'target']) {
    const value = args[key]
    if (typeof value === 'string' && /^https?:\/\//i.test(value)) return value
  }
  return ''
}

/** Tools that talk to the network themselves, outside the fetch layer. */
const NET_TOOLS = new Set(['web_fetch', 'web_search', 'http_request'])

function blockedEvent(exec, reason) {
  return {
    id: ++state.seq,
    at: Date.now(),
    channel: 'tool',
    method: 'CALL',
    host: '',
    url: String((exec && exec.name) || 'tool'),
    by: callerPackage(),
    tier: 'unknown',
    marks: [],
    data: '未知',
    model: '',
    outcome: 'blocked',
    status: 0,
    error: String(reason || '已拦截').slice(0, 240),
  }
}

function buildSnapshot() {
  const now = Date.now()
  const since = now - MAX_AGE_MS
  const events = state.events.filter((event) => event.at >= since).slice().reverse()
  const hosts = new Map()
  const plugins = new Set()

  for (const event of events) {
    if (event.by && event.by !== 'unknown') plugins.add(event.by)
    const key = event.host || `工具：${event.url}`
    let row = hosts.get(key)
    if (!row) {
      row = { host: key, tier: event.tier, data: event.data, count: 0, lastAt: 0, plugins: [], outcomes: {}, marks: [], risk: 0, channels: [] }
      hosts.set(key, row)
    }
    row.count += 1
    row.lastAt = Math.max(row.lastAt, event.at)
    if (!row.plugins.includes(event.by)) row.plugins.push(event.by)
    if (!row.channels.includes(event.channel)) row.channels.push(event.channel)
    if ((DATA_RANK[event.data] || 0) > (DATA_RANK[row.data] || 0)) row.data = event.data
    row.outcomes[event.outcome] = (row.outcomes[event.outcome] || 0) + 1
    for (const mark of event.marks || []) {
      const rank = STRENGTH_RANK[mark.strength] || 0
      const seen = row.marks.find((item) => item.rule === mark.rule)
      if (seen) seen.count += 1
      else row.marks.push({ rule: mark.rule, label: mark.label, detail: mark.detail || '', strength: mark.strength, count: 1 })
      if (rank > row.risk) row.risk = rank
    }
  }

  for (const row of hosts.values()) {
    row.marks.sort((a, b) => (STRENGTH_RANK[b.strength] || 0) - (STRENGTH_RANK[a.strength] || 0))
  }

  // Most concerning first, then most recent: a lookalike domain must not hide
  // under a chatty official row.
  const destinations = [...hosts.values()].sort((a, b) => (b.risk - a.risk) || (b.lastAt - a.lastAt))

  return {
    ok: true,
    now,
    startedAt: state.startedAt,
    watching: state.watching,
    sockets: state.sockets,
    lastSeenAt: state.lastSeenAt,
    stalled: state.lastSeenAt ? now - state.lastSeenAt > STALL_MS : now - state.startedAt > STALL_MS,
    plugins: [...plugins],
    destinations,
    events,
  }
}

export function apply(ctx) {
  ctx.effect(installFetch, 'egress-audit: fetch observation')
  ctx.effect(installNet, 'egress-audit: socket observation')
  ctx.effect(() => () => {
    state.tag = null
  }, 'egress-audit: tag reset')

  ctx.on('llm/stream', (options, next) => {
    try {
      const model = (options && (options.model || options.modelId)) || ''
      state.tag = { until: Date.now() + LLM_WINDOW_MS, channel: 'llm', data: '对话内容', model: String(model) }
    } catch {
      /* never disturb the call */
    }
    return typeof next === 'function' ? next() : undefined
  })

  ctx.on('tools/pre-execute', async (exec, next) => {
    if (typeof next !== 'function') return undefined
    let decision
    try {
      decision = await next()
    } catch (error) {
      try {
        record(blockedEvent(exec, (error && error.message) || error))
      } catch {
        /* observation only */
      }
      throw error
    }
    try {
      if (decision && decision.kind && decision.kind !== 'allow') {
        record(blockedEvent(exec, decision.reason || `已拦截（${decision.kind}）`))
      }
    } catch {
      /* observation only */
    }
    return decision
  })

  // Tools that reach the network on their own: the built-in web tools import
  // undici's fetch directly, so the byte-level layers may only see a proxy hop.
  // Their own call report is the honest record of where the request went.
  ctx.on('tools/post-execute', async (exec, result, next) => {
    if (typeof next !== 'function') return result
    try {
      const tool = String((exec && exec.name) || '')
      if (NET_TOOLS.has(tool)) {
        const url = extractUrl(exec && exec.arguments)
        const failed = Boolean(result && result.isError)
        const host = url ? parseUrl(url).host : ''
        const redundant = host && state.events.some((item) => item.host === host && Date.now() - item.at < 15000)
        if (!redundant) {
          const event = url
            ? makeEvent({ url, method: 'CALL', by: callerPackage(), size: 0, channel: 'tool', data: '未知' })
            : {
              id: ++state.seq,
              at: Date.now(),
              channel: 'tool',
              method: 'CALL',
              host: '',
              url: tool,
              by: callerPackage(),
              tier: 'unknown',
              marks: [],
              data: '未知',
              model: '',
              outcome: 'attempted',
              status: 0,
              error: '',
            }
          event.tool = tool
          event.outcome = failed ? 'failed' : 'sent'
          if (failed) {
            const reason = (result.error && result.error.message) || '调用失败'
            event.error = `[${tool}] ${String(reason)}`.slice(0, 240)
          }
          record(event)
        }
      }
    } catch {
      /* observation only */
    }
    return next()
  })

  if (!ctx.webServer || typeof ctx.webServer.register !== 'function') return

  ctx.effect(() => ctx.webServer.register({
    kind: 'exact',
    path: ROUTE,
    handler: (req, res) => {
      try {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          res.writeHead(405, { 'content-type': 'text/plain; charset=utf-8' })
          res.end('read-only')
          return
        }
        const body = JSON.stringify(buildSnapshot())
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
          'content-length': Buffer.byteLength(body),
        })
        res.end(req.method === 'HEAD' ? undefined : body)
      } catch (error) {
        try {
          res.writeHead(500, { 'content-type': 'application/json; charset=utf-8' })
          res.end(JSON.stringify({ ok: false, error: String((error && error.message) || error) }))
        } catch {
          /* response already gone */
        }
      }
    },
  }), 'egress-audit: snapshot route')
}
