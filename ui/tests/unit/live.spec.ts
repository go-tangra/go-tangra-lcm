import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { coalesce, RELOAD_DELAY, useLive } from '@/stores/live'
import { stubFetch } from './helpers'
import { useCertificates } from '@/stores/certificates'

// A minimal EventSource double capturing listeners.
class FakeES {
  static last: FakeES | null = null
  url: string
  listeners: Record<string, (e: MessageEvent) => void> = {}
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  closed = false
  constructor(url: string) {
    this.url = url
    FakeES.last = this
  }
  addEventListener(t: string, fn: (e: MessageEvent) => void): void {
    this.listeners[t] = fn
  }
  close(): void {
    this.closed = true
  }
}

describe('live store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.stubGlobal('EventSource', FakeES as unknown as typeof EventSource)
  })

  afterEach(() => vi.useRealTimers())

  it('opens one shared stream; certificate events reload the page once per burst', async () => {
    vi.useFakeTimers()
    const fetch = stubFetch(() => ({ status: 200, body: { items: [{ id: 'c2', spiffe_id: 'spiffe://example.org/svc/b', status: 'active' }], total: 2, page: 1 } }))
    const certs = useCertificates()
    const live = useLive()
    const release1 = live.connect()
    const release2 = live.connect() // shares the connection
    expect(FakeES.last?.url).toContain('/gateway/v1/stream')
    FakeES.last?.onopen?.()
    expect(live.connected).toBe(true)

    // Before the table was loaded, events do not fetch anything.
    live._emit('certificate.issued', '{"id":"c0"}')
    await vi.advanceTimersByTimeAsync(RELOAD_DELAY)
    expect(fetch).not.toHaveBeenCalled()

    await certs.list({ status: 'active' }, { page: 2, page_size: 10, sort: 'not_after', order: 'asc' })
    certs.items = [{ id: 'c1', spiffe_id: 'spiffe://example.org/svc/a', status: 'active' }]
    fetch.mockClear()
    live._emit('certificate.issued', '{"id":"c2","spiffe_id":"spiffe://example.org/svc/b","status":"active"}')
    live._emit('certificate.revoked', '{"id":"c1"}')
    // A revocation patches the visible row at once; nothing is inserted client-side.
    expect(certs.items.map((c) => [c.id, c.status])).toEqual([['c1', 'revoked']])
    live._emit('certificate.renewed', '{"certificate_id":"c1"}')
    expect(fetch).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(RELOAD_DELAY)
    // One reload of the current page, same filter, page, size and sort.
    expect(fetch).toHaveBeenCalledTimes(1)
    const url = String(fetch.mock.calls[0]?.[0])
    expect(url).toContain('status=active')
    expect(url).toContain('page=2&page_size=10&sort=not_after&order=asc')
    expect(certs.items.map((c) => c.id)).toEqual(['c2'])

    const seen: string[] = []
    const off = live.on((type) => seen.push(type))
    live._emit('job.failed', '{"id":"j1"}')
    expect(seen).toContain('job.failed')
    off()

    // Closing drops a pending reload.
    live._emit('certificate.issued', '{"id":"c3"}')
    release1()
    expect(FakeES.last?.closed).toBe(false)
    release2()
    expect(FakeES.last?.closed).toBe(true)
    await vi.advanceTimersByTimeAsync(RELOAD_DELAY)
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('coalesces bursts and can cancel', () => {
    vi.useFakeTimers()
    const fn = vi.fn()
    const c = coalesce(fn, 100)
    c.trigger()
    c.trigger()
    vi.advanceTimersByTime(100)
    expect(fn).toHaveBeenCalledTimes(1)
    c.trigger()
    c.cancel()
    vi.advanceTimersByTime(100)
    expect(fn).toHaveBeenCalledTimes(1)
  })
})
