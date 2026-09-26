import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { plugins, stubFetch } from './helpers'
import Issuers from '@/views/issuers/index.vue'
import Certificates from '@/views/certificates/index.vue'
import Permissions from '@/views/permissions/index.vue'
import Dashboard from '@/views/dashboard/index.vue'
import Audit from '@/views/audit/index.vue'
import Secrets from '@/views/secrets/index.vue'
import Requests from '@/views/requests/index.vue'
import HeaderCert from '@/components/HeaderCert.vue'
import { issuerSchema, issueSvidSchema, issueAcmeSchema, secretSchema, webhookSchema, providerHint, FREYA_DNS_PROVIDER, requestFilterSchema } from '@/schemas'

class FakeSource { onopen = null; onerror = null; addEventListener() {} close() {} }
const mountView = (c: unknown) => mount(c as never, { global: { plugins: plugins() }, attachTo: document.body })
const drawer = () => document.body.querySelector('aside[role=dialog]')!

describe('lcm schemas', () => {
  it('issuer: ACME requires directory/email/provider; secrets marker is dropped', () => {
    expect(issuerSchema.safeParse({ name: 'a', type: 'self_signed', trust_domain: 'example.org', key_type: 'ecdsa-p256', validity_ceiling_days: 90 }).success).toBe(true)
    const acme = issuerSchema.safeParse({ name: 'a', type: 'acme', trust_domain: 'example.org', key_type: 'ecdsa-p256', validity_ceiling_days: 90, directory: '', email: '', dns_provider: '' })
    expect(acme.success).toBe(false)
    expect(acme.success ? [] : acme.error.issues.map((i) => i.path[0])).toEqual(['directory', 'email', 'dns_provider'])
    expect(issuerSchema.parse({ name: 'a', type: 'self_signed', trust_domain: 'example.org', key_type: 'rsa-2048', validity_ceiling_days: '30', eab_hmac_key: '__set__' }).eab_hmac_key).toBeUndefined()
    expect(issuerSchema.safeParse({ name: 'a', type: 'self_signed', trust_domain: 'bad domain', key_type: 'rsa-2048', validity_ceiling_days: 1 }).success).toBe(false)
  })
  it('issue: SPIFFE id shape, domain lists, PEM guard; secrets/webhooks; grants', () => {
    expect(issueSvidSchema.safeParse({ spiffe_id: 'spiffe://example.org/svc/api', dns_sans: 'a.example, b.example', validity_days: 30 }).data).toMatchObject({ dns_sans: ['a.example', 'b.example'] })
    expect(issueSvidSchema.safeParse({ spiffe_id: 'api', validity_days: 30 }).success).toBe(false)
    expect(issueSvidSchema.safeParse({ spiffe_id: 'spiffe://example.org/x', validity_days: 30, csr_pem: 'not pem' }).success).toBe(false)
    expect(issueAcmeSchema.safeParse({ issuer_id: 'i', domains: 'example.com, *.example.com' }).data).toMatchObject({ domains: ['example.com', '*.example.com'], auto_renew: true })
    expect(issueAcmeSchema.safeParse({ issuer_id: 'i', domains: '' }).success).toBe(false)
    expect(secretSchema.parse({ name: 's', kind: 'dns_credential', value: 'plain-token' })).toEqual({ name: 's', kind: 'dns_credential', value: { value: 'plain-token' } })
    expect(secretSchema.parse({ name: 's', kind: 'dns_credential', value: '{"k":"v"}' }).value).toEqual({ k: 'v' })
    expect(secretSchema.safeParse({ name: 's', kind: 'dns_credential', value: '{broken' }).success).toBe(false)
    expect(webhookSchema.safeParse({ name: 'w', url: 'http://insecure.test', event_types: 'certificate.issued' }).success).toBe(false)
    expect(webhookSchema.parse({ name: 'w', url: 'https://hooks.test/x', event_types: 'certificate.issued, certificate.revoked' }).event_types).toEqual(['certificate.issued', 'certificate.revoked'])
  })
})

describe('issuers view', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.stubGlobal('EventSource', FakeSource)
  })

  it('loads DNS providers for an ACME issuer and keeps a stored secret as the marker', async () => {
    const bodies: Array<Record<string, unknown>> = []
    const issuer = { id: 'i1', name: 'acme', type: 'acme' as const, trust_domain: 'example.org', is_default: false, settings: { dns_provider: 'route53', email: 'ops@x.test', directory: 'https://acme.test/dir' }, permissions: { delete: true } }
    stubFetch((url, init) => {
      if (url.endsWith('/dns-providers')) return { status: 200, body: { items: [{ name: 'route53', display_name: 'AWS Route 53', fields: [{ key: 'access_key', label: 'Access key', secret: false, required: true }, { key: 'secret_key', label: 'Secret key', secret: true, required: true }] }] } }
      if (init?.method === 'PUT') {
        bodies.push(JSON.parse(String(init.body)))
        return { status: 200, body: issuer }
      }
      if (url.includes('/issuers') && (!init || init.method === 'GET')) return { status: 200, body: { items: [issuer] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Issuers)
    await flushPromises()
    await w.find('[data-test="issuer-row-i1"]').trigger('click')
    await flushPromises()
    expect(drawer().querySelector('[data-test="issuer-dns-provider"]')).toBeTruthy()
    const secret = drawer().querySelector<HTMLInputElement>('[data-test="issuer-cred-secret_key"] input')!
    expect(secret.value).toBe('__set__')
    expect(secret.type).toBe('password')
    ;(drawer().querySelector('[data-test="issuer-save"]') as HTMLButtonElement).click()
    await flushPromises()
    // The unchanged secret marker is not resent.
    expect(bodies[0]?.secrets).toBeUndefined()
    expect(bodies[0]?.settings).toMatchObject({ dns_provider: 'route53', email: 'ops@x.test' })
    w.unmount()
  })

  it('Freya DNS: no credential inputs, a hosted-zone hint, and no secrets sent', async () => {
    expect(providerHint(FREYA_DNS_PROVIDER)).toContain('DNS module')
    expect(providerHint('route53')).toBe('')
    const bodies: Array<Record<string, unknown>> = []
    const issuer = { id: 'i2', name: 'le', type: 'acme' as const, trust_domain: 'example.org', is_default: false, settings: { dns_provider: 'freya-dns', email: 'ops@x.test', directory: 'https://acme.test/dir' }, permissions: { delete: true } }
    stubFetch((url, init) => {
      if (url.endsWith('/dns-providers')) return { status: 200, body: { items: [{ name: 'route53', display_name: 'AWS Route 53', fields: [{ key: 'secret_key', label: 'Secret key', secret: true, required: true }] }, { name: 'freya-dns', display_name: 'Freya DNS', fields: [] }] } }
      if (init?.method === 'PUT') {
        bodies.push(JSON.parse(String(init.body)))
        return { status: 200, body: issuer }
      }
      if (url.includes('/issuers') && (!init || init.method === 'GET')) return { status: 200, body: { items: [issuer] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Issuers)
    await flushPromises()
    await w.find('[data-test="issuer-row-i2"]').trigger('click')
    await flushPromises()
    expect(drawer().querySelector('[data-test="issuer-dns-hint"]')?.textContent).toContain('hosted in a zone')
    expect(drawer().querySelector('[data-test^="issuer-cred-"]')).toBeNull()
    ;(drawer().querySelector('[data-test="issuer-save"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(bodies[0]?.secrets).toBeUndefined()
    expect(bodies[0]?.settings).toMatchObject({ dns_provider: 'freya-dns' })
    w.unmount()
  })

  it('shows a scrubbed validation error and blocks empty submits client-side', async () => {
    const calls: string[] = []
    stubFetch((url, init) => {
      if (url.endsWith('/dns-providers')) return { status: 200, body: { items: [] } }
      if (init?.method === 'POST') {
        calls.push(url)
        return { status: 422, body: { reason: 'validation_failed', detail: { fields: { trust_domain: 'already in use' } } } }
      }
      return { status: 200, body: { items: [] } }
    })
    const w = mountView(Issuers)
    await flushPromises()
    await w.find('[data-test="issuer-new"]').trigger('click')
    await flushPromises()
    ;(drawer().querySelector('[data-test="issuer-save"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(calls.length).toBe(0)
    const name = drawer().querySelector<HTMLInputElement>('input[data-field=name]')!
    name.value = 'mesh'
    name.dispatchEvent(new Event('input'))
    const td = drawer().querySelector<HTMLInputElement>('input[data-field=trust_domain]')!
    td.value = 'example.org'
    td.dispatchEvent(new Event('input'))
    ;(drawer().querySelector('[data-test="issuer-save"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(calls.length).toBe(1)
    expect(drawer().textContent).toContain('already in use')
    w.unmount()
  })
})

describe('certificates view', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.stubGlobal('EventSource', FakeSource)
  })
  it('downloads the bundle and offers revoke for a writable active certificate; request dialog validates SPIFFE ids', async () => {
    const cert = { id: 'c1', serial: '01', spiffe_id: 'spiffe://example.org/svc/api', status: 'active' as const, permissions: { write: true } }
    const posts: string[] = []
    stubFetch((url, init) => {
      if (url.endsWith('/certificates/c1/download')) return { status: 200, body: { certificate: { id: 'c1' }, cert_pem: 'C', chain_pem: 'CH', bundle_pem: 'B' } }
      if (init?.method === 'POST') {
        posts.push(url)
        return { status: 202, body: { status: 'processing', spiffe_id: 'x' } }
      }
      if (url.includes('/certificates')) return { status: 200, body: { items: [cert] } }
      return { status: 200, body: { items: [] } }
    })
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: () => 'blob:x', revokeObjectURL: () => {} }))
    const w = mountView(Certificates)
    await flushPromises()
    await w.find('[data-test="cert-row-c1"]').trigger('click')
    await flushPromises()
    expect(drawer().querySelector('[data-test="cert-status"]')?.textContent).toContain('active')
    expect(drawer().querySelector('[data-test="cert-revoke"]')).toBeTruthy()
    ;(drawer().querySelector('[data-test="cert-download-bundle"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(drawer().querySelector('[data-test="cert-error"]')).toBeNull()
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    await flushPromises()
    await w.find('[data-test="cert-issue-open"]').trigger('click')
    await flushPromises()
    const dialog = document.body.querySelector('[data-test=issue-dialog]')!
    const spiffe = dialog.querySelector<HTMLInputElement>('input[data-field=spiffe_id]')!
    spiffe.value = 'not-a-spiffe-id'
    spiffe.dispatchEvent(new Event('input'))
    ;(dialog.querySelector('[data-test="issue-submit"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(posts.length).toBe(0)
    expect(dialog.querySelector('[role=alert]')?.textContent).toContain('SPIFFE')
    spiffe.value = 'spiffe://example.org/svc/web'
    spiffe.dispatchEvent(new Event('input'))
    ;(dialog.querySelector('[data-test="issue-submit"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(posts).toEqual(['/api/lcm/v1/certificates/issue'])
    expect(dialog.querySelector('[data-test="issue-queued"]')).toBeTruthy()
    w.unmount()
  })
  it('an ACME order is acknowledged as processing and points to Requests', async () => {
    const posts: string[] = []
    stubFetch((url, init) => {
      if (init?.method === 'POST') {
        posts.push(url)
        return { status: 202, body: { status: 'processing', domains: ['www.example.org'], request_id: 'r7' } }
      }
      if (url.includes('/issuers')) return { status: 200, body: { items: [{ id: 'i1', name: 'le', type: 'acme', trust_domain: 'example.org', settings: {} }] } }
      return { status: 200, body: { items: [] } }
    })
    const w = mountView(Certificates)
    await flushPromises()
    await w.find('[data-test="cert-issue-open"]').trigger('click')
    await flushPromises()
    const dialog = document.body.querySelector('[data-test=issue-dialog]')!
    const acmeTab = Array.from(dialog.querySelectorAll('[role=tab]')).find((t) => t.textContent?.includes('ACME')) as HTMLElement
    acmeTab.click()
    await flushPromises()
    const issuer = dialog.querySelector<HTMLSelectElement>('select[data-field=issuer_id]')!
    issuer.value = 'i1'
    issuer.dispatchEvent(new Event('change'))
    const domains = dialog.querySelector<HTMLInputElement>('input[data-field=domains]')!
    domains.value = 'www.example.org'
    domains.dispatchEvent(new Event('input'))
    ;(dialog.querySelector('[data-test="issue-submit"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(posts).toEqual(['/api/lcm/v1/certificates/acme'])
    const queued = dialog.querySelector('[data-test="issue-queued"]')!
    expect(queued.textContent).toContain('processing')
    expect(queued.textContent).toContain('Requests')
    expect(dialog.querySelector('[data-test="issue-requests-link"]')?.getAttribute('href')).toBe('/lcm/requests')
    w.unmount()
  })
  it('opens the certificate named in the ?id= query', async () => {
    const cert = { id: 'c9', serial: '09', sans: ['www.example.org'], kind: 'generic' as const, status: 'active' as const, permissions: { write: true } }
    stubFetch((url) => {
      if (url.endsWith('/certificates/c9')) return { status: 200, body: cert }
      if (url.includes('/certificates')) return { status: 200, body: { items: [] } }
      return { status: 200, body: { items: [] } }
    })
    const pl = plugins()
    const router = pl[0] as import('vue-router').Router
    await router.push('/lcm/certificates?id=c9')
    await router.isReady()
    const w = mount(Certificates as never, { global: { plugins: pl }, attachTo: document.body })
    await flushPromises()
    expect(document.body.querySelector('[data-test="certificate-drawer"]')?.textContent).toContain('www.example.org')
    w.unmount()
  })
})

describe('requests view', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('shows ACME orders by their domains with processing/failed states, the failure reason and a link to the issued certificate', async () => {
    expect(requestFilterSchema.safeParse({ status: 'processing' }).success).toBe(true)
    expect(requestFilterSchema.safeParse({ status: 'failed' }).success).toBe(true)
    const items = [
      { id: 'r1', kind: 'svid', spiffe_id: 'spiffe://example.org/svc/a', sans: [], status: 'pending' },
      { id: 'r2', kind: 'generic', spiffe_id: '', sans: ['*.example.org', 'example.org'], status: 'processing' },
      { id: 'r3', kind: 'generic', spiffe_id: '', sans: ['test.example.org'], status: 'failed', reason: 'acme: order failed: Domain name is redundant with a wildcard domain' },
      { id: 'r4', kind: 'generic', spiffe_id: '', sans: ['www.example.org'], status: 'issued', certificate_id: 'c9' },
    ]
    const queries: string[] = []
    stubFetch((url) => {
      if (url.includes('/requests?')) {
        queries.push(url)
        return { status: 200, body: { items } }
      }
      return { status: 200, body: { items: [] } }
    })
    const w = mountView(Requests)
    await flushPromises()
    const row = (id: string) => w.find('[data-test="request-row-' + id + '"]')
    expect(row('r1').text()).toContain('spiffe://example.org/svc/a')
    expect(row('r2').text()).toContain('*.example.org, example.org')
    expect(row('r2').text()).toContain('processing')
    expect(row('r2').text()).toContain('generic')
    expect(row('r3').text()).toContain('failed')
    expect(row('r3').text()).toContain('redundant with a wildcard domain')
    expect(w.find('[data-test="request-approve-r1"]').exists()).toBe(true)
    for (const id of ['r2', 'r3', 'r4']) {
      expect(w.find('[data-test="request-approve-' + id + '"]').exists()).toBe(false)
      expect(w.find('[data-test="request-reject-' + id + '"]').exists()).toBe(false)
    }
    expect(w.find('[data-test="request-cert-r4"]').attributes('href')).toContain('/lcm/certificates?id=c9')
    expect(w.find('[data-test="request-cert-r3"]').exists()).toBe(false)
    const options = Array.from(w.find('[data-test="requests-filter"]').element.querySelectorAll('option')).map((o) => o.textContent?.trim())
    expect(options).toEqual(expect.arrayContaining(['processing', 'failed']))
    w.unmount()
  })
})

describe('permissions view', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('offers only relations at or below the holder and lists grants by name', async () => {
    stubFetch((url) => {
      if (url.includes('/grants?')) return { status: 200, body: { items: [{ id: 'g1', subject_type: 'user', subject_id: 'u1', relation: 'viewer' }] } }
      if (url.includes('/access/effective')) return { status: 200, body: { relation: 'sharer', permissions: { share: true }, grants: [] } }
      if (url.endsWith('/api/v1/users/lookup')) return { status: 200, body: { items: [{ id: 'u1', display_name: 'Ana' }] } }
      if (url.startsWith('/api/v1/roles')) return { status: 200, body: [] }
      if (url.includes('/certificates')) return { status: 200, body: { items: [{ id: 'c1', spiffe_id: 'spiffe://example.org/svc/api', status: 'active' }] } }
      return { status: 200, body: { items: [] } }
    })
    const w = mountView(Permissions)
    await flushPromises()
    await w.find('[data-test="perm-certificate-c1"]').trigger('click')
    await flushPromises()
    expect(drawer().querySelector('#perm-level')).toBeTruthy()
    expect(Array.from(drawer().querySelectorAll('#perm-level option')).map((o) => o.textContent)).toEqual(['viewer', 'sharer'])
    expect(drawer().textContent).toContain('Ana')
    expect(drawer().textContent).toContain('Your relation: sharer')
    w.unmount()
  })
  it('hides the grant form without share', async () => {
    stubFetch((url) => {
      if (url.includes('/grants?')) return { status: 200, body: { items: [] } }
      if (url.includes('/access/effective')) return { status: 200, body: { relation: 'viewer', permissions: {}, grants: [] } }
      if (url.startsWith('/api/v1/roles')) return { status: 200, body: [] }
      if (url.includes('/issuers')) return { status: 200, body: { items: [{ id: 'i1', name: 'mesh', type: 'self_signed', trust_domain: 'example.org', settings: {} }] } }
      return { status: 200, body: { items: [] } }
    })
    const w = mountView(Permissions)
    await flushPromises()
    await w.find('[data-test="perm-issuer-i1"]').trigger('click')
    await flushPromises()
    expect(drawer().querySelector('#perm-subject')).toBeNull()
    expect(drawer().textContent).toContain('share permission')
    w.unmount()
  })
})

describe('dashboard, audit, secrets and header', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.stubGlobal('EventSource', FakeSource)
  })
  it('renders stat tiles, audit rows with resolved names, and the header badge', async () => {
    const stats = { certificates: { active: 2, expiring: 1 }, issuers: 3, jobs: { queued: 1 }, clients: 4, expiring_soon: 1, recent_errors: 0, open_streams: 5 }
    stubFetch((url) => {
      if (url.endsWith('/api/v1/users/lookup')) return { status: 200, body: { items: [{ id: 'u1', display_name: 'Ana' }] } }
      if (url.startsWith('/api/v1/roles')) return { status: 200, body: [] }
      if (url.includes('/stats')) return { status: 200, body: stats }
      if (url.includes('/audit')) return { status: 200, body: { items: [{ ts: '2024-01-01T00:00:00Z', event_type: 'certificate_issued', actor_kind: 'user', actor_id: 'u1', subject_name: 'spiffe://example.org/svc/api', outcome: 'ok', details: {} }] } }
      return { status: 200, body: { items: [] } }
    })
    const d = mountView(Dashboard)
    await flushPromises()
    expect(d.find('[data-test="stat-certificates"]').text()).toContain('3')
    expect(d.find('[data-test="stat-issuers"]').text()).toContain('3')
    expect(d.findAll('progress').length).toBe(2)
    d.unmount()
    const a = mountView(Audit)
    await flushPromises()
    expect(a.find('[data-test="audit-table"]').text()).toContain('Ana')
    expect(a.find('[data-test="audit-table"]').text()).toContain('spiffe://example.org/svc/api')
    a.unmount()
    const h = mountView(HeaderCert)
    await flushPromises()
    expect(h.find('[data-test="cert-badge"]').text()).toBe('1')
    await h.find('[data-test="cert-button"]').trigger('click')
    expect(h.find('[data-test="cert-events-empty"]').exists()).toBe(true)
    expect(h.find('[style]').exists()).toBe(false)
    h.unmount()
  })
  it('secrets: value is write-only and cleared after saving; webhook needs https', async () => {
    const posts: Record<string, unknown>[] = []
    stubFetch((url, init) => {
      if (init?.method === 'POST' && url.endsWith('/secrets')) {
        posts.push(JSON.parse(String(init.body)))
        return { status: 201, body: { id: 's1', name: 'dns', kind: 'dns_credential' } }
      }
      return { status: 200, body: { items: [] } }
    })
    const w = mountView(Secrets)
    await flushPromises()
    await w.find('[data-test="secret-new"]').trigger('click')
    await flushPromises()
    const name = drawer().querySelector<HTMLInputElement>('input[data-field=name]')!
    name.value = 'dns'
    name.dispatchEvent(new Event('input'))
    const value = drawer().querySelector<HTMLTextAreaElement>('textarea[data-field=value]')!
    value.value = 'TOP-SECRET-TOKEN'
    value.dispatchEvent(new Event('input'))
    ;(drawer().querySelector('[data-test="secret-save"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(posts[0]).toEqual({ name: 'dns', kind: 'dns_credential', value: { value: 'TOP-SECRET-TOKEN' } })
    expect(document.body.textContent).not.toContain('TOP-SECRET-TOKEN')
    const url = w.find('input[data-field=url]')
    await url.setValue('http://plain.test/hook')
    await w.find('input[data-field=name]').setValue('hook')
    await w.find('input[data-field=event_types]').setValue('certificate.issued')
    await w.findAll('form')[0]!.trigger('submit')
    await flushPromises()
    expect(w.text()).toContain('https')
    w.unmount()
  })
})
