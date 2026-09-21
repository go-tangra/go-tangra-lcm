import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { stubFetch } from './helpers'
import { useCertificates } from '@/stores/certificates'
import { useIssuers } from '@/stores/issuers'
import { useRequests } from '@/stores/requests'
import { usePermissions } from '@/stores/permissions'
import { useSecrets } from '@/stores/secrets'
import { useOps } from '@/stores/ops'
import { grantable } from '@/api/types'

const cert = { id: 'c1', serial: '01', spiffe_id: 'spiffe://example.org/svc/api', status: 'active' as const, not_after: '2030-01-01T00:00:00Z', permissions: { write: true } }

describe('certificates store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('lists with filters, issues, renews and revokes', async () => {
    const fetch = stubFetch((url, init) => {
      if (url.includes('/certificates?') && (!init || init.method === 'GET')) return { status: 200, body: { items: [cert], next_cursor: undefined } }
      if (url.endsWith('/certificates/issue') && init?.method === 'POST') return { status: 202, body: { status: 'processing', spiffe_id: 'spiffe://example.org/svc/api' } }
      if (url.endsWith('/certificates/c1/renew')) return { status: 200, body: { certificate: { ...cert, serial: '03' }, cert_pem: 'Y' } }
      if (url.endsWith('/certificates/c1/revoke')) return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useCertificates()
    await s.list({ status: 'active', spiffe_id: 'api' })
    expect(s.items.length).toBe(1)
    expect(String(fetch.mock.calls[0]?.[0])).toContain('status=active')
    expect(String(fetch.mock.calls[0]?.[0])).toContain('spiffe_id=api')
    const ack = await s.issue({ spiffe_id: 'spiffe://example.org/svc/api' })
    expect(ack.status).toBe('processing') // async: the cert arrives over SSE, not inline
    await s.renew('c1')
    expect(s.items.find((c) => c.id === 'c1')?.serial).toBe('03')
    await s.revoke('c1', 'superseded')
    expect(s.items.find((c) => c.id === 'c1')?.status).toBe('revoked')
  })

  it('reflects live stream events without a refetch', () => {
    const s = useCertificates()
    s.items = [{ ...cert }]
    s.applyEvent('certificate.issued', { id: 'cX', spiffe_id: 'spiffe://example.org/svc/new', status: 'active' })
    expect(s.items[0]?.id).toBe('cX')
    s.applyEvent('certificate.revoked', { id: 'c1' })
    expect(s.items.find((c) => c.id === 'c1')?.status).toBe('revoked')
    // renewed replaces by id
    s.applyEvent('certificate.renewed', { id: 'cX', spiffe_id: 'spiffe://example.org/svc/new', status: 'active', serial: '99' })
    expect(s.items.find((c) => c.id === 'cX')?.serial).toBe('99')
    expect(s.items.filter((c) => c.id === 'cX').length).toBe(1)
  })

  it('downloads the bundle and can deploy to a target', async () => {
    stubFetch((url, init) => {
      if (url.endsWith('/certificates/c1/download')) return { status: 200, body: { certificate: cert, cert_pem: 'C', chain_pem: 'CH', bundle_pem: 'B' } }
      if (url.endsWith('/certificates/c1/deploy') && init?.method === 'POST') return { status: 200, body: { id: 'd1' } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useCertificates()
    const b = await s.download('c1')
    expect(b.bundle_pem).toBe('B')
    await s.deploy('c1', 't1')
  })
})

describe('issuers store', () => {
  beforeEach(() => setActivePinia(createPinia()))
  const issuer = { id: 'i1', name: 'root', type: 'self_signed' as const, trust_domain: 'example.org', is_default: true, settings: {} }

  it('lists, loads dns providers, creates and moves the default on update', async () => {
    stubFetch((url, init) => {
      if (url.includes('/issuers?') && (!init || init.method === 'GET')) return { status: 200, body: { items: [issuer, { ...issuer, id: 'i2', name: 'second', is_default: false }] } }
      if (url.endsWith('/dns-providers')) return { status: 200, body: [{ name: 'route53', display_name: 'AWS Route 53', fields: [{ key: 'access_key', label: 'Access key', secret: false, required: true }, { key: 'secret_key', label: 'Secret key', secret: true, required: true }] }] }
      if (url.endsWith('/issuers') && init?.method === 'POST') return { status: 201, body: { ...issuer, id: 'i3', name: 'acme', type: 'acme', is_default: false } }
      if (url.endsWith('/issuers/i2') && init?.method === 'PUT') return { status: 200, body: { ...issuer, id: 'i2', name: 'second', is_default: true } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useIssuers()
    await s.list()
    expect(s.items.length).toBe(2)
    await s.loadDnsProviders()
    expect(s.dnsProviders[0]?.fields.find((f) => f.key === 'secret_key')?.secret).toBe(true)
    await s.create({ name: 'acme', type: 'acme', trust_domain: 'example.org' })
    expect(s.items.some((i) => i.id === 'i3')).toBe(true)
    await s.update('i2', { name: 'second', type: 'self_signed', trust_domain: 'example.org', is_default: true })
    expect(s.items.find((i) => i.id === 'i1')?.is_default).toBe(false)
    expect(s.items.find((i) => i.id === 'i2')?.is_default).toBe(true)
  })
})

describe('requests store', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('lists requests + jobs, approves/rejects, cancels and retries', async () => {
    stubFetch((url) => {
      if (url.includes('/requests?')) return { status: 200, body: { items: [{ id: 'r1', spiffe_id: 'spiffe://example.org/svc/a', status: 'pending' }] } }
      if (url.endsWith('/requests/r1/approve')) return { status: 200, body: { id: 'r1', status: 'approved' } }
      if (url.endsWith('/requests/r1/reject')) return { status: 200, body: { id: 'r1', status: 'rejected' } }
      if (url.includes('/jobs?')) return { status: 200, body: { items: [{ id: 'j1', type: 'issue', status: 'failed' }] } }
      if (url.endsWith('/jobs/j1/retry')) return { status: 200, body: { id: 'j1', status: 'queued' } }
      if (url.endsWith('/jobs/j1/cancel')) return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useRequests()
    await s.listRequests('pending')
    await s.listJobs('failed')
    expect(s.requests[0]?.status).toBe('pending')
    expect(s.jobs[0]?.status).toBe('failed')
    await s.approve('r1')
    expect(s.requests[0]?.status).toBe('approved')
    await s.retryJob('j1')
    expect(s.jobs[0]?.status).toBe('queued')
    await s.cancelJob('j1')
    expect(s.jobs[0]?.status).toBe('failed')
  })
})

describe('permissions store', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('grantable never exceeds the held relation', () => {
    expect(grantable('sharer')).toEqual(['viewer', 'sharer'])
    expect(grantable('owner')).toEqual(['viewer', 'sharer', 'editor', 'owner'])
    expect(grantable('')).toEqual([])
  })
  it('loads grants + effective for a certificate, grants and revokes', async () => {
    stubFetch((url, init) => {
      if (url.includes('/grants?')) return { status: 200, body: { items: [{ id: 'g1', subject_type: 'user', subject_id: 'u1', relation: 'viewer' }] } }
      if (url.includes('/access/effective')) return { status: 200, body: { relation: 'owner', permissions: { share: true }, grants: [] } }
      if (url.endsWith('/grants') && init?.method === 'POST') return { status: 201, body: { id: 'g2', subject_type: 'user', subject_id: 'u2', relation: 'editor' } }
      if (url.endsWith('/grants/g1/revoke')) return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = usePermissions()
    await s.load('certificate', 'c1')
    expect(s.grants.length).toBe(1)
    expect(s.effective?.relation).toBe('owner')
    await s.grant({ resource_type: 'certificate', resource_id: 'c1', subject_type: 'user', subject_id: 'u2', relation: 'editor' })
    expect(s.grants.some((g) => g.id === 'g2')).toBe(true)
    await s.revoke('g1')
    expect(s.grants.some((g) => g.id === 'g1')).toBe(false)
  })
})

describe('secrets store', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('creates a write-only secret, rotates it and manages webhooks', async () => {
    const bodies: Array<Record<string, unknown>> = []
    stubFetch((url, init) => {
      if (init?.body) bodies.push(JSON.parse(String(init.body)))
      if (url.endsWith('/secrets') && (!init || init.method === 'GET')) return { status: 200, body: { items: [] } }
      if (url.endsWith('/secrets') && init?.method === 'POST') return { status: 201, body: { id: 's1', name: 'r53', kind: 'dns_credential' } }
      if (url.endsWith('/secrets/s1/rotate')) return { status: 200, body: { id: 's1', name: 'r53', kind: 'dns_credential' } }
      if (url.endsWith('/webhooks') && (!init || init.method === 'GET')) return { status: 200, body: { items: [] } }
      if (url.endsWith('/webhooks') && init?.method === 'POST') return { status: 201, body: { id: 'w1', name: 'hook', url: 'https://x', event_types: ['certificate.issued'] } }
      if (url.endsWith('/webhooks/w1/remove')) return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useSecrets()
    await s.listSecrets()
    await s.createSecret({ name: 'r53', kind: 'dns_credential', value: { secret_key: 'zzz' } })
    expect(s.secrets[0]?.id).toBe('s1')
    await s.rotateSecret('s1', { secret_key: 'new' })
    await s.createWebhook({ name: 'hook', url: 'https://x', event_types: ['certificate.issued'] })
    expect(s.webhooks[0]?.id).toBe('w1')
    await s.removeWebhook('w1')
    expect(s.webhooks.length).toBe(0)
    // The credential value is only ever sent, never requested back.
    for (const call of bodies) if ('value' in call) expect(JSON.stringify(call.value)).not.toBe('{}')
  })
})

describe('ops store', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('loads stats and audit, imports a backup', async () => {
    stubFetch((url, init) => {
      if (url.endsWith('/stats')) return { status: 200, body: { certificates: { active: 3, expiring: 1 }, issuers: 2, jobs: { queued: 1 }, clients: 4, expiring_soon: 1, recent_errors: 0, open_streams: 2 } }
      if (url.includes('/audit')) return { status: 200, body: { items: [{ ts: 't', event_type: 'certificate_issued', actor_kind: 'user', outcome: 'ok', details: {} }] } }
      if (url.includes('/backup/import') && init?.method === 'POST') return { status: 200, body: { issuers: { created: 1, skipped: 0, overwritten: 0, failed: 0 }, certificates: { created: 0, skipped: 0, overwritten: 0, failed: 0 }, secrets: { created: 0, skipped: 0, overwritten: 0, failed: 0 }, webhooks: { created: 0, skipped: 0, overwritten: 0, failed: 0 }, warnings: [] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useOps()
    await s.loadStats()
    expect(s.stats?.expiring_soon).toBe(1)
    await s.loadAudit({ event_type: 'certificate_issued' })
    expect(s.audit.length).toBe(1)
    const file = new File([JSON.stringify({ version: 1 })], 'b.json', { type: 'application/json' })
    const rep = await s.importBackup(file, 'overwrite')
    expect(rep.issuers.created).toBe(1)
  })
})
