// Server paging and sorting of the lcm tables (go-tangra
// specs/032-server-side-tables): each table asks for one page with the
// server's sort fields, shows the total (which counts only what the caller
// may read), keeps page / size / sort in the URL, adopts the server-clamped
// page, returns to page 1 on a filter change, and the certificates table
// reloads its current page (debounced) on live certificate events instead of
// inserting rows client-side.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'
import { createRouter, createMemoryHistory } from 'vue-router'
import { abilitiesPlugin } from '@casl/vue'
import { createMongoAbility } from '@casl/ability'
import { nextTick, type Plugin } from 'vue'
import Certificates from '@/views/certificates/index.vue'
import Issuers from '@/views/issuers/index.vue'
import Requests from '@/views/requests/index.vue'
import Secrets from '@/views/secrets/index.vue'
import Audit from '@/views/audit/index.vue'
import Permissions from '@/views/permissions/index.vue'
import { RELOAD_DELAY } from '@/stores/live'

type Call = { url: string; init: RequestInit }
function fetchMock(handler: (url: string, init: RequestInit) => unknown): Call[] {
  const calls: Call[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({ url: String(url), init })
    return new Response(JSON.stringify(handler(String(url), init)), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
  return calls
}
class FakeSource {
  static instances: FakeSource[] = []
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  listeners = new Map<string, (e: MessageEvent) => void>()
  constructor() { FakeSource.instances.push(this) }
  addEventListener(t: string, fn: (e: MessageEvent) => void) { this.listeners.set(t, fn) }
  close() {}
  emit(t: string, data: unknown) { this.listeners.get(t)?.(new MessageEvent(t, { data: JSON.stringify(data) })) }
}
const newRouter = () => createRouter({ history: createMemoryHistory(), routes: [{ path: '/:pathMatch(.*)*', component: { template: '<div/>' } }] })
const ability = (): [Plugin, ...unknown[]] => [abilitiesPlugin as Plugin, createMongoAbility([{ action: 'manage', subject: 'all' }]), { useGlobalProperties: true }]
const params = (url: string) => new URL(url, 'https://x').searchParams
const pathOf = (url: string) => new URL(url, 'https://x').pathname
const header = (w: ReturnType<typeof mount>, label: string) => w.findAll('th button').find((b) => b.text().startsWith(label))
const cert = (n: number) => ({ id: 'c' + n, kind: 'svid', serial: String(n), spiffe_id: 'spiffe://example.org/svc/' + n, status: 'active', not_after: '2030-01-01T00:00:00Z', created_at: '2026-01-01T00:00:00Z', permissions: {} })

/** A server of `total` rows per paged list that echoes the request and clamps the page. */
function server(total = 130) {
  return (url: string) => {
    const q = params(url)
    if (!q.has('page')) return { items: [] }
    const size = Number(q.get('page_size'))
    const page = Math.min(Number(q.get('page')), Math.max(1, Math.ceil(total / size)))
    const path = pathOf(url)
    const row = path.endsWith('/certificates') ? cert(page) : path.endsWith('/audit') ? { id: String(page), ts: '2026-01-01T00:00:00Z', event_type: 'x', actor_kind: 'system', outcome: 'ok' } : { id: 'r' + page, name: 'Row ' + page, type: 'self_signed', status: 'pending', kind: 'dns_credential', event_types: [] }
    return { items: [row], total, page, page_size: size, sort: q.get('sort'), order: q.get('order') }
  }
}

beforeEach(() => {
  setActivePinia(createPinia())
  document.cookie = '__Host-csrf=tok; Secure; Path=/'
  vi.stubGlobal('EventSource', FakeSource)
  FakeSource.instances = []
  ;(globalThis as unknown as { __vw: number }).__vw = 1280
})

describe('certificates table', () => {
  it('pages with the total, sorts the whole list on the server, filters return to page 1', async () => {
    const calls = fetchMock(server(130))
    const w = mount(Certificates, { global: { plugins: [newRouter(), ability()] }, attachTo: document.body })
    await flushPromises()
    const lists = () => calls.filter((c) => pathOf(c.url).endsWith('/certificates') && params(c.url).has('page'))
    const last = () => params(lists().at(-1)!.url)
    expect(lists()[0]!.url).toBe('/api/lcm/v1/certificates?page=1&page_size=25&sort=created_at&order=desc')
    // The issuer select loads the readable issuers by name (one large page).
    const opts = calls.find((c) => pathOf(c.url).endsWith('/issuers'))!
    expect([params(opts.url).get('page_size'), params(opts.url).get('sort')]).toEqual(['200', 'name'])
    expect(w.text()).toContain('Showing 1–25 of 130')
    await w.find('[aria-label="Page 3"]').trigger('click')
    await flushPromises()
    expect(last().get('page')).toBe('3')
    const sortable = w.findAll('th button').map((b) => b.text())
    for (const label of ['Identity', 'Kind', 'Status', 'Not after', 'Issued']) expect(sortable.some((t) => t.startsWith(label)), label).toBe(true)
    expect(sortable.some((t) => t.startsWith('Serial'))).toBe(false)
    await header(w, 'Identity')!.trigger('click')
    await flushPromises()
    expect([last().get('sort'), last().get('order'), last().get('page')]).toEqual(['identity', 'asc', '1'])
    await w.find('[aria-label="Page 2"]').trigger('click')
    await flushPromises()
    // A filter change returns to page 1 and keeps the sort.
    await w.find('[data-test="cert-filter-spiffe"] input').setValue('spiffe://example.org/svc/1')
    await w.find('[data-test="cert-filter-spiffe"] input').trigger('keyup', { key: 'Enter' })
    await flushPromises()
    expect([last().get('spiffe_id'), last().get('page'), last().get('sort')]).toEqual(['spiffe://example.org/svc/1', '1', 'identity'])
    expect(last().has('cursor') || last().has('limit')).toBe(false)
    w.unmount()
  })

  it('a burst of certificate events reloads the current page once; other events do not', async () => {
    vi.useFakeTimers()
    try {
      const calls = fetchMock(server(60))
      const r = newRouter()
      await r.push('/lcm/certificates?certificates.page=2&certificates.sort=not_after')
      const w = mount(Certificates, { global: { plugins: [r, ability()] } })
      await flushPromises()
      const lists = () => calls.filter((c) => pathOf(c.url).endsWith('/certificates') && params(c.url).has('page'))
      const before = lists().length
      const src = FakeSource.instances[0]!
      src.emit('certificate.issued', { certificate_id: 'cA' })
      src.emit('certificate.renewed', { certificate_id: 'cB' })
      src.emit('certificate.revoked', { id: 'c2' })
      await nextTick()
      // The revoked row on screen is patched at once; nothing is inserted.
      expect(w.find('[data-test="cert-status-c2"]').text()).toContain('revoked')
      expect(w.find('[data-test="cert-row-cA"]').exists()).toBe(false)
      await vi.advanceTimersByTimeAsync(RELOAD_DELAY)
      await flushPromises()
      expect(lists().length).toBe(before + 1)
      const again = params(lists().at(-1)!.url)
      expect([again.get('page'), again.get('sort'), again.get('order')]).toEqual(['2', 'not_after', 'asc'])
      src.emit('job.completed', { id: 'j1' })
      src.emit('request.created', { id: 'r1' })
      await vi.advanceTimersByTimeAsync(RELOAD_DELAY)
      expect(lists().length).toBe(before + 1)
      w.unmount()
    } finally {
      vi.useRealTimers()
    }
  })

  it('page, size and sort live in the URL; the server-clamped page is adopted; unknown sorts fall back', async () => {
    const r = newRouter()
    await r.push('/lcm/certificates?certificates.page=9&certificates.size=10&certificates.sort=not_after&certificates.order=desc')
    await r.isReady()
    const calls = fetchMock(server(31))
    const w = mount(Certificates, { global: { plugins: [r, ability()] } })
    await flushPromises()
    const first = params(calls.find((c) => pathOf(c.url).endsWith('/certificates'))!.url)
    expect([first.get('page'), first.get('page_size'), first.get('sort'), first.get('order')]).toEqual(['9', '10', 'not_after', 'desc'])
    expect(r.currentRoute.value.query['certificates.page']).toBe('4') // server clamped 9 → 4
    w.unmount()
    await r.push('/lcm/certificates?certificates.sort=fingerprint_sha256')
    const calls2 = fetchMock(server(31))
    const w2 = mount(Certificates, { global: { plugins: [r, ability()] } })
    await flushPromises()
    expect(params(calls2.find((c) => pathOf(c.url).endsWith('/certificates'))!.url).get('sort')).toBe('created_at')
    w2.unmount()
  })
})

describe('other lcm tables', () => {
  it('issuers, requests, jobs, secrets, webhooks, audit and permissions ask for server pages', async () => {
    for (const [view, key, expected] of [
      [Issuers, 'issuers', [['/issuers', 'name', 'asc', '25']]],
      [Requests, 'requests', [['/requests', 'created_at', 'desc', '25'], ['/jobs', 'created_at', 'desc', '25']]],
      [Secrets, 'secrets', [['/secrets', 'name', 'asc', '25'], ['/webhooks', 'name', 'asc', '25']]],
      [Audit, 'audit', [['/audit', 'ts', 'desc', '50']]],
      [Permissions, 'permissions', [['/certificates', 'identity', 'asc', '25'], ['/issuers', 'name', 'asc', '25']]],
    ] as const) {
      setActivePinia(createPinia())
      const calls = fetchMock(server(80))
      const w = mount(view as never, { global: { plugins: [newRouter(), ability()] }, attachTo: document.body })
      await flushPromises()
      for (const [path, sort, order, size] of expected) {
        const c = calls.find((x) => pathOf(x.url).endsWith(path) && params(x.url).get('page_size') === size)
        expect(c, key + ' ' + path).toBeTruthy()
        const q = params(c!.url)
        expect([q.get('page'), q.get('sort'), q.get('order')], key + ' ' + path).toEqual(['1', sort, order])
        expect(q.has('cursor') || q.has('limit')).toBe(false)
      }
      expect(w.text()).toContain('of 80')
      w.unmount()
    }
  })

  it('audit explains the default 7-day window and drops it when from/to are set', async () => {
    const calls = fetchMock(server(3))
    const w = mount(Audit, { global: { plugins: [newRouter(), ability()] }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test="audit-window"]').text()).toContain('last 7 days')
    expect(params(calls.at(-1)!.url).has('from')).toBe(false)
    await w.find('[data-test="audit-filter-from"] input').setValue('2026-01-01')
    await w.find('[data-test="audit-apply"]').trigger('click')
    await flushPromises()
    expect(params(calls.at(-1)!.url).get('from')).toContain('2026-01-01')
    expect(w.find('[data-test="audit-window"]').exists()).toBe(false)
    w.unmount()
  })
})
