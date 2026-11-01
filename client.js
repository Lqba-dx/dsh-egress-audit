/**
 * Client half of the egress audit: one read-only settings page.
 *
 * It only reads the Host snapshot over HTTP. It never sends anything except
 * that GET, and it stores the user's hidden rows in localStorage.
 */

window.__ModuleLoader__.load({
  id: 'dsh-egress-audit',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    const ENDPOINT = '/dsh-egress/snapshot.json'
    const HIDDEN_KEY = 'dsh.egress.audit.hidden'

    const C = {
      border: 'var(--dsw-alias-border-l1)',
      text: 'var(--dsw-alias-label-primary)',
      dim: 'var(--dsw-alias-label-secondary)',
      warn: 'var(--dsw-alias-state-warn-primary)',
      error: 'var(--dsw-alias-state-error-primary)',
      ok: 'var(--dsw-alias-state-success-primary)',
      idle: 'var(--dsw-alias-state-idle-primary)',
      brand: 'var(--dsw-alias-brand-primary)',
      layer1: 'var(--dsw-alias-bg-layer-1)',
    }

    const TIERS = {
      official: { label: '官方已知', color: C.ok },
      external: { label: '外部第三方', color: C.warn },
      suspicious: { label: '疑似伪装', color: C.error },
      local: { label: '本机', color: C.idle },
      unknown: { label: '未知', color: C.dim },
    }

    const OUTCOMES = {
      sent: { label: '已发出', color: C.ok },
      blocked: { label: '被拦截', color: C.error },
      failed: { label: '失败', color: C.warn },
      attempted: { label: '进行中', color: C.idle },
    }

    const CHANNELS = {
      llm: '对话请求',
      http: '网络请求',
      tcp: '直接连接',
      tool: '工具调用',
    }

    // One shared column template per table keeps every row aligned no matter how
    // long a host name or a package list is.
    const DEST_COLS = 'minmax(0, 1.7fr) 88px 72px 38px minmax(0, 1.3fr) 62px'
    const EVENT_COLS = '62px minmax(0, 1.1fr) minmax(0, 1.9fr) 62px 58px'

    function readHidden() {
      try {
        const raw = window.localStorage.getItem(HIDDEN_KEY)
        const parsed = raw ? JSON.parse(raw) : []
        return Array.isArray(parsed) ? parsed.filter((item) => typeof item === 'string') : []
      } catch {
        return []
      }
    }

    function writeHidden(list) {
      try {
        window.localStorage.setItem(HIDDEN_KEY, JSON.stringify(list))
      } catch {
        /* a full storage must not break the page */
      }
    }

    function clock(at) {
      try {
        return new Date(at).toLocaleTimeString('zh-CN', { hour12: false })
      } catch {
        return ''
      }
    }

    function minutes(value) {
      return Math.max(1, Math.round(value / 60000))
    }

    function headline(snap, hidden) {
      if (!snap) return '正在读取…'
      const span = minutes((snap.now || Date.now()) - (snap.startedAt || Date.now()))
      const destinations = snap.destinations || []
      if (!destinations.length) return `已监控 ${span} 分钟，还没有观测到任何外发数据。`

      const plugins = (snap.plugins || []).length
      const outside = destinations.filter((item) => item.tier !== 'official' && item.tier !== 'local')
      const suspect = outside.filter((item) => item.tier === 'suspicious')
      const content = outside.filter((item) => item.data === '对话内容')
      let text = `过去 ${span} 分钟内，${plugins} 个插件向 ${destinations.length} 个目的地发送过数据。`

      if (!outside.length) {
        const relay = destinations.some((item) => item.tier === 'local')
        return relay ? `${text}目前只看到官方渠道和本机转发。` : `${text}目前全部是官方渠道。`
      }
      if (suspect.length) text += `其中 ${suspect.length} 个带着可疑标记`
      else text += `其中 ${outside.length} 个不是官方渠道`
      if (content.length) text += `，${content.length} 个收到过对话内容`
      text += '。'
      if (hidden.size) text += ` 你隐藏了 ${hidden.size} 个目的地，它们仍在上面的计数里。`
      return text
    }

    function rowStyle(columns) {
      return {
        display: 'grid',
        gridTemplateColumns: columns,
        alignItems: 'start',
        gap: '8px',
        padding: '7px 10px',
        borderBottom: `1px solid ${C.border}`,
        fontSize: '12px',
        lineHeight: '1.45',
      }
    }

    function cell(extra) {
      return {
        minWidth: 0,
        ...extra,
      }
    }

    function Tag({ text, color }) {
      return h('span', {
        style: {
          display: 'inline-block',
          maxWidth: '100%',
          padding: '1px 5px',
          borderRadius: '4px',
          border: `1px solid ${color}`,
          color,
          fontSize: '11px',
          lineHeight: '16px',
          whiteSpace: 'nowrap',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          verticalAlign: 'top',
        },
      }, text)
    }

    const MARK_COLOR = { strong: C.error, medium: C.warn, weak: C.dim, info: C.idle }

    /**
     * One destination's evidence. A mark is only ever shown together with the
     * rule that produced it (in the tooltip), so nothing here is an opinion the
     * user cannot check.
     */
    function Marks({ marks, compact }) {
      if (!marks || !marks.length) return null
      const shown = marks.slice(0, compact ? 2 : 3)
      const rest = marks.length - shown.length
      return h('span', { style: { display: 'inline-flex', gap: '4px', alignItems: 'center', flexWrap: 'wrap', minWidth: 0 } }, [
        ...shown.map((mark) => h('span', {
          key: mark.rule,
          title: mark.detail ? `${mark.detail}（命中 ${mark.count} 次）` : mark.label,
          style: {
            padding: '0 5px',
            borderRadius: '3px',
            border: `1px dashed ${MARK_COLOR[mark.strength] || C.dim}`,
            color: MARK_COLOR[mark.strength] || C.dim,
            fontSize: '10px',
            lineHeight: '15px',
            whiteSpace: 'nowrap',
            cursor: 'help',
          },
        }, mark.label)),
        rest > 0
          ? h('span', { key: 'rest', style: { color: C.dim, fontSize: '10px' }, title: marks.slice(shown.length).map((m) => m.label).join('、') }, `+${rest}`)
          : null,
      ])
    }

    function Panel() {
      const [snap, setSnap] = React.useState(null)
      const [failure, setFailure] = React.useState('')
      const [hidden, setHidden] = React.useState(() => new Set(readHidden()))
      const [showHidden, setShowHidden] = React.useState(false)

      React.useEffect(() => {
        let alive = true
        const tick = async () => {
          try {
            const response = await fetch(ENDPOINT, { cache: 'no-store' })
            if (!response.ok) throw new Error(`HTTP ${response.status}`)
            const body = await response.json()
            if (alive) {
              setSnap(body)
              setFailure('')
            }
          } catch (error) {
            if (alive) setFailure(String((error && error.message) || error))
          }
        }
        tick()
        const timer = setInterval(tick, 2000)
        return () => {
          alive = false
          clearInterval(timer)
        }
      }, [])

      const toggle = (host) => {
        const next = new Set(hidden)
        if (next.has(host)) next.delete(host)
        else next.add(host)
        setHidden(next)
        writeHidden([...next])
      }

      const destinations = (snap && snap.destinations) || []
      const visible = destinations
        .filter((item) => showHidden || !hidden.has(item.host))
        .slice()
        .sort((a, b) => (hidden.has(a.host) ? 1 : 0) - (hidden.has(b.host) ? 1 : 0))
      const events = ((snap && snap.events) || []).slice(0, 40)
      const stalled = Boolean(snap && snap.stalled)

      return h('div', { style: { display: 'flex', flexDirection: 'column', gap: '14px', color: C.text, fontSize: '13px' } }, [
        h('div', { key: 'head', style: { display: 'flex', flexDirection: 'column', gap: '6px' } }, [
          h('div', { key: 't', style: { fontWeight: 600, fontSize: '14px' } }, '数据外发审计'),
          h('div', { key: 's', style: { color: C.dim, fontSize: '12px' } },
            '只读观测：显示 Harness 和插件把数据发往了哪里、发的是什么、有没有被拦截。它自己不联网、不落盘、不改动任何流量。'),
        ]),

        h('div', { key: 'conclusion', style: { padding: '10px 12px', border: `1px solid ${C.border}`, borderRadius: '8px', background: C.layer1, lineHeight: '1.6' } },
          headline(snap, hidden)),

        failure
          ? h('div', { key: 'fail', style: { color: C.error, fontSize: '12px' } }, `读取快照失败：${failure}`)
          : null,

        !snap || snap.watching === false
          ? h('div', { key: 'watch', style: { color: C.warn, fontSize: '12px' } },
            '网络观测钩子未生效，这份视图可能不完整。')
          : null,

        snap && snap.sockets === false
          ? h('div', { key: 'sock', style: { color: C.warn, fontSize: '12px' } },
            '连接层兜底未生效：直接调用 undici 或原始 socket 的流量这次看不到。')
          : null,

        stalled
          ? h('div', { key: 'stale', style: { color: C.dim, fontSize: '12px' } },
            snap.lastSeenAt
              ? `已有一段时间没有观测到任何外发（最后一条 ${clock(snap.lastSeenAt)}），监控可能已经失效。`
              : '启用后一直没有任何记录，可能没接上，试试重启这个插件。')
          : null,

        h('div', { key: 'dests', style: { border: `1px solid ${C.border}`, borderRadius: '8px', overflow: 'hidden' } }, [
          h('div', { key: 'h', style: { ...rowStyle(DEST_COLS), background: C.layer1, color: C.dim, fontWeight: 600 } }, [
            h('div', { key: 'a', style: cell() }, '目的地'),
            h('div', { key: 'b', style: cell() }, '分级'),
            h('div', { key: 'c', style: cell() }, '内容'),
            h('div', { key: 'd', style: cell({ textAlign: 'right' }) }, '次数'),
            h('div', { key: 'e', style: cell() }, '发起插件'),
            h('div', { key: 'f', style: cell({ textAlign: 'right' }) }, '操作'),
          ]),
          visible.length === 0
            ? h('div', { key: 'empty', style: { ...rowStyle('1fr'), color: C.dim } },
              destinations.length ? '这些目的地都被你隐藏了，勾选下面的选项查看。' : '暂无条目。')
            : visible.map((item) => {
              const tier = TIERS[item.tier] || TIERS.unknown
              const muted = hidden.has(item.host)
              const marks = item.marks || []
              return h('div', { key: item.host, style: { ...rowStyle(DEST_COLS), opacity: muted ? 0.55 : 1 } }, [
                h('div', { key: 'h', style: cell({ display: 'flex', flexDirection: 'column', gap: '2px' }) }, [
                  h('div', { key: 'n', title: item.host, style: { wordBreak: 'break-all' } }, item.host || '（无主机）'),
                  marks.length ? h(Marks, { key: 'm', marks }) : null,
                ]),
                h('div', { key: 't', style: cell({ paddingTop: '1px' }) }, h(Tag, { text: tier.label, color: tier.color })),
                h('div', { key: 'c', style: cell({ color: item.data === '对话内容' ? C.warn : C.dim, paddingTop: '1px', wordBreak: 'break-all' }) }, item.data),
                h('div', { key: 'n', style: cell({ textAlign: 'right', color: C.dim, paddingTop: '1px' }) }, String(item.count)),
                h('div', { key: 'p', style: cell({ color: C.dim, fontSize: '11px', paddingTop: '1px', wordBreak: 'break-all' }) },
                  item.plugins.join(', ') || '无法确定'),
                h('div', { key: 'x', style: cell({ textAlign: 'right', paddingTop: '1px' }) },
                  h('button', {
                    type: 'button',
                    onClick: () => toggle(item.host),
                    title: muted ? '重新显示这一行（记录一直都在）' : '从这张表里隐藏（记录照旧，不影响发送，也不影响上面的结论）',
                    style: {
                      border: `1px solid ${C.border}`,
                      borderRadius: '6px',
                      background: 'transparent',
                      color: C.dim,
                      fontSize: '11px',
                      padding: '2px 5px',
                      cursor: 'pointer',
                      whiteSpace: 'nowrap',
                    },
                  }, muted ? '取消隐藏' : '隐藏')),
              ])
            }),
        ]),

        h('label', { key: 'show', style: { display: 'flex', alignItems: 'center', gap: '6px', color: C.dim, fontSize: '12px' } }, [
          h('input', {
            key: 'i',
            type: 'checkbox',
            checked: showHidden,
            onChange: (event) => setShowHidden(event.target.checked),
          }),
          h('span', { key: 's' }, `显示已隐藏的目的地（${hidden.size}）`),
        ]),

        h('div', { key: 'events', style: { border: `1px solid ${C.border}`, borderRadius: '8px', overflow: 'hidden' } }, [
          h('div', { key: 'h', style: { ...rowStyle(EVENT_COLS), background: C.layer1, color: C.dim, fontWeight: 600 } }, [
            h('div', { key: 'a', style: cell() }, '时间'),
            h('div', { key: 'b', style: cell() }, '发起方'),
            h('div', { key: 'c', style: cell() }, '目的地'),
            h('div', { key: 'd', style: cell() }, '内容'),
            h('div', { key: 'e', style: cell() }, '结果'),
          ]),
          events.length === 0
            ? h('div', { key: 'empty', style: { ...rowStyle('1fr'), color: C.dim } }, '最近没有观测到外发事件。')
            : events.map((event) => {
              const outcome = OUTCOMES[event.outcome] || OUTCOMES.attempted
              const target = event.host || event.url
              return h('div', { key: event.id, style: rowStyle(EVENT_COLS) }, [
                h('div', { key: 'a', style: cell({ color: C.dim, fontSize: '11px' }) }, clock(event.at)),
                h('div', { key: 'b', style: cell({ display: 'flex', flexDirection: 'column', gap: '1px' }) }, [
                  h('div', { key: 'n', title: event.by, style: { fontSize: '11px', wordBreak: 'break-all' } }, event.by),
                  h('div', { key: 'c', style: { color: C.dim, fontSize: '10px', wordBreak: 'break-all' } },
                    event.tool ? `${CHANNELS[event.channel] || event.channel} · ${event.tool}` : CHANNELS[event.channel] || event.channel),
                ]),
                h('div', { key: 'c', style: cell({ display: 'flex', flexDirection: 'column', gap: '2px' }) }, [
                  h('div', { key: 'u', title: event.url, style: { wordBreak: 'break-all' } }, target),
                  event.marks && event.marks.length ? h(Marks, { key: 'm', marks: event.marks, compact: true }) : null,
                  event.error ? h('div', { key: 'e', style: { color: C.error, fontSize: '11px', wordBreak: 'break-word' } }, event.error) : null,
                ]),
                h('div', { key: 'd', style: cell({ color: event.data === '对话内容' ? C.warn : C.dim, fontSize: '11px' }) },
                  event.data),
                h('div', { key: 'e', style: cell() }, h(Tag, { text: outcome.label, color: outcome.color })),
              ])
            }),
        ]),

        h('div', { key: 'note', style: { color: C.dim, fontSize: '11px', lineHeight: '1.7' } }, [
          h('div', { key: 'a' }, '· 分级只看客观证据：官方已知（主机名与官方名单精确相等）/ 本机 / 外部第三方 / 疑似伪装（命中任一红色标记）。'),
          h('div', { key: 'b' }, '· 标记旁的数字是命中次数，悬停可看依据：形近字域名、夹带官方名、形近官方域名、直接用 IP、局域网地址、明文传输、非常规端口。'),
          h('div', { key: 'c' }, '· 隐藏只是把这一行从表里收起来：记录、计数、上面的结论都不变，更不会影响发送行为。'),
          h('div', { key: 'd' }, '· 看不到的地方：MCP 子进程（独立进程，钩子进不去）、Web Worker、加密隧道里的内容，以及本插件启用之前的流量。'),
        ]),
      ])
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: 'egress-audit',
          order: 22,
          label: '数据外发',
        }, Panel))
      },
    }
  },
})
