import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { stubFetch } from './helpers'
import { useCertificates } from '@/stores/certificates'
import { useIssuers } from '@/stores/issuers'
import { useJobList, useRequestList, useRequests } from '@/stores/requests'
import { usePermissions } from '@/stores/permissions'
import { useSecretList, useSecrets, useWebhookList } from '@/stores/secrets'
import { useAuditList, useOps } from '@/stores/ops'
import { grantable } from '@/api/types'

const cert = { id: 'c1', serial: '01', spiffe_id: 'spiffe://example.org/svc/api', status: 'active' as const, not_after: '2030-01-01T00:00:00Z', permissions: { write: true } }

describe('certificates store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('lists with filters, issues, renews and revokes', async () => {
    const fetch = stubFetch((url, init) => {
      if (url.includes('/certificates?') && (!init || init.method === 'GET')) return { status: 200, body: { items: [cert], total: 1, page: 1, page_size: 25, sort: 'created_at', order: 'desc' } }
      if (url.endsWith('/certificates/issue') && init?.method === 'POST') return { status: 202, body: { status: 'processing', spiffe_id: 'spiffe://example.org/svc/api' } }
      if (url.endsWith('/certificates/c1/renew')) return { status: 200, body: { certificate: { ...cert, serial: '03' }, cert_pem: 'Y' } }
      if (url.endsWith('/certificates/c1/revoke')) return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useCertificates()
    await s.list({ status: 'active', spiffe_id: 'api' })
    expect(s.items.length).toBe(1)
    expect(s.total).toBe(1)
    const first = String(fetch.mock.calls[0]?.[0])
    expect(first).toContain('status=active')
    expect(first).toContain('spiffe_id=api')
    expect(first).toContain('page=1&page_size=25&sort=created_at&order=desc')
    expect(first).not.toContain('cursor')
    const ack = await s.issue({ spiffe_id: 'spiffe://example.org/svc/api' })
    expect(ack.status).toBe('processing') // async: the cert arrives over SSE, not inline
    const calls = fetch.mock.calls.length
    const bundle = await s.renew('c1')
    expect(bundle.certificate.serial).toBe('03')
    await Promise.resolve()
    // The renewal reloads the current page (with the same filter) instead of inserting a row.
    expect(String(fetch.mock.calls[calls + 1]?.[0])).toContain('status=active')
    await s.revoke('c1', 'superseded')
    expect(s.items.find((c) => c.id === 'c1')?.status).toBe('revoked')
  })

  it('patches a revocation in place but never inserts rows from live events', () => {
    const s = useCertificates()
    s.items = [{ ...cert }]
    s.applyEvent('certificate.issued', { id: 'cX', spiffe_id: 'spiffe://example.org/svc/new', status: 'active' })
    expect(s.items.map((c) => c.id)).toEqual(['c1'])
    s.applyEvent('certificate.revoked', { id: 'c1' })
    expect(s.items.find((c) => c.id === 'c1')?.status).toBe('revoked')
    s.applyEvent('certificate.renewed', { certificate_id: 'c1' })
    expect(s.items.length).toBe(1)
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
      if (url.includes('/issuers?') && (!init || init.method === 'GET')) return { status: 200, body: { items: [issuer, { ...issuer, id: 'i2', name: 'second', is_default: false }], total: 2, page: 1 } }
      if (url.endsWith('/dns-providers')) return { status: 200, body: { items: [{ name: 'route53', display_name: 'AWS Route 53', fields: [{ key: 'access_key', label: 'Access key', secret: false, required: true }, { key: 'secret_key', label: 'Secret key', secret: true, required: true }] }] } }
      if (url.endsWith('/issuers') && init?.method === 'POST') return { status: 201, body: { ...issuer, id: 'i3', name: 'acme', type: 'acme', is_default: false } }
      if (url.endsWith('/issuers/i2') && init?.method === 'PUT') return { status: 200, body: { ...issuer, id: 'i2', name: 'second', is_default: true } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useIssuers()
    await s.list()
    expect(s.items.length).toBe(2)
    expect(s.total).toBe(2)
    await s.loadOptions()
    expect(s.options.map((i) => i.id)).toEqual(['i1', 'i2'])
    await s.loadDnsProviders()
    expect(s.dnsProviders[0]?.fields.find((f) => f.key === 'secret_key')?.secret).toBe(true)
    const created = await s.create({ name: 'acme', type: 'acme', trust_domain: 'example.org' })
    expect(created.id).toBe('i3') // the view reloads the page
    await s.update('i2', { name: 'second', type: 'self_signed', trust_domain: 'example.org', is_default: true })
    expect(s.items.find((i) => i.id === 'i1')?.is_default).toBe(false)
    expect(s.items.find((i) => i.id === 'i2')?.is_default).toBe(true)
  })
})

describe('requests store', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('lists requests + jobs, approves/rejects, cancels and retries', async () => {
    stubFetch((url) => {
      if (url.includes('/requests?')) return { status: 200, body: { items: [{ id: 'r1', spiffe_id: 'spiffe://example.org/svc/a', status: 'pending' }], total: 1 } }
      if (url.endsWith('/requests/r1/approve')) return { status: 200, body: { id: 'r1', status: 'approved' } }
      if (url.endsWith('/requests/r1/reject')) return { status: 200, body: { id: 'r1', status: 'rejected' } }
      if (url.includes('/jobs?')) return { status: 200, body: { items: [{ id: 'j1', type: 'issue', status: 'failed' }], total: 1 } }
      if (url.endsWith('/jobs/j1/retry')) return { status: 200, body: { id: 'j1', status: 'queued' } }
      if (url.endsWith('/jobs/j1/cancel')) return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useRequests()
    const requests = useRequestList()
    const jobs = useJobList()
    await requests.list({ status: 'pending' })
    await jobs.list({ status: 'failed' })
    expect(requests.items[0]?.status).toBe('pending')
    expect(requests.total).toBe(1)
    expect(jobs.items[0]?.status).toBe('failed')
    await s.approve('r1')
    expect(requests.items[0]?.status).toBe('approved')
    await s.retryJob('j1')
    expect(jobs.items[0]?.status).toBe('queued')
    await s.cancelJob('j1')
    expect(jobs.items[0]?.status).toBe('failed')
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
      if (url.includes('/secrets?') && (!init || init.method === 'GET')) return { status: 200, body: { items: [{ id: 's1', name: 'r53', kind: 'dns_credential' }], total: 1 } }
      if (url.endsWith('/secrets') && init?.method === 'POST') return { status: 201, body: { id: 's1', name: 'r53', kind: 'dns_credential' } }
      if (url.endsWith('/secrets/s1/rotate')) return { status: 200, body: { id: 's1', name: 'r53', kind: 'dns_credential' } }
      if (url.includes('/webhooks?') && (!init || init.method === 'GET')) return { status: 200, body: { items: [], total: 0 } }
      if (url.endsWith('/webhooks') && init?.method === 'POST') return { status: 201, body: { id: 'w1', name: 'hook', url: 'https://x', event_types: ['certificate.issued'] } }
      if (url.endsWith('/webhooks/w1/remove')) return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useSecrets()
    const list = useSecretList()
    const hooks = useWebhookList()
    const created = await s.createSecret({ name: 'r53', kind: 'dns_credential', value: { secret_key: 'zzz' } })
    expect(created.id).toBe('s1')
    await list.list()
    expect(list.items[0]?.id).toBe('s1')
    expect(list.total).toBe(1)
    await s.rotateSecret('s1', { secret_key: 'new' })
    const hook = await s.createWebhook({ name: 'hook', url: 'https://x', event_types: ['certificate.issued'] })
    expect(hook.id).toBe('w1')
    await s.removeWebhook('w1')
    await hooks.list()
    expect(hooks.items.length).toBe(0)
    // The credential value is only ever sent, never requested back.
    for (const call of bodies) if ('value' in call) expect(JSON.stringify(call.value)).not.toBe('{}')
  })
})

describe('ops store', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('loads stats and audit, imports a backup', async () => {
    stubFetch((url, init) => {
      if (url.endsWith('/stats')) return { status: 200, body: { certificates: { active: 3, expiring: 1 }, issuers: 2, jobs: { queued: 1 }, clients: 4, expiring_soon: 1, recent_errors: 0, open_streams: 2 } }
      if (url.includes('/audit')) return { status: 200, body: { items: [{ id: '1', ts: 't', event_type: 'certificate_issued', actor_kind: 'user', outcome: 'ok', details: {} }], total: 1, page: 1, page_size: 50, sort: 'ts', order: 'desc' } }
      if (url.includes('/backup/import') && init?.method === 'POST') return { status: 200, body: { issuers: { created: 1, skipped: 0, overwritten: 0, failed: 0 }, certificates: { created: 0, skipped: 0, overwritten: 0, failed: 0 }, secrets: { created: 0, skipped: 0, overwritten: 0, failed: 0 }, webhooks: { created: 0, skipped: 0, overwritten: 0, failed: 0 }, warnings: [] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const s = useOps()
    await s.loadStats()
    expect(s.stats?.expiring_soon).toBe(1)
    const audit = useAuditList()
    await audit.list({ event_type: 'certificate_issued' })
    expect(audit.items.length).toBe(1)
    expect(audit.total).toBe(1)
    const file = new File([JSON.stringify({ version: 1 })], 'b.json', { type: 'application/json' })
    const rep = await s.importBackup(file, 'overwrite')
    expect(rep.issuers.created).toBe(1)
  })
})
