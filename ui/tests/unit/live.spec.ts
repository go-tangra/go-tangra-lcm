import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useLive } from '@/stores/live'
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

  it('opens one shared stream and reflects certificate events in the list', () => {
    const certs = useCertificates()
    certs.items = [{ id: 'c1', spiffe_id: 'spiffe://example.org/svc/a', status: 'active' }]
    const live = useLive()
    const release1 = live.connect()
    const release2 = live.connect() // shares the connection
    expect(FakeES.last?.url).toContain('/gateway/v1/stream')
    FakeES.last?.onopen?.()
    expect(live.connected).toBe(true)

    live._emit('certificate.issued', '{"id":"c2","spiffe_id":"spiffe://example.org/svc/b","status":"active"}')
    expect(certs.items[0]?.id).toBe('c2')
    live._emit('certificate.revoked', '{"id":"c1"}')
    expect(certs.items.find((c) => c.id === 'c1')?.status).toBe('revoked')

    const seen: string[] = []
    const off = live.on((type) => seen.push(type))
    live._emit('job.failed', '{"id":"j1"}')
    expect(seen).toContain('job.failed')
    off()

    release1()
    expect(FakeES.last?.closed).toBe(false)
    release2()
    expect(FakeES.last?.closed).toBe(true)
  })
})
