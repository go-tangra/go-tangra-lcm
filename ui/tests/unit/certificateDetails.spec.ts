// The certificate drawer's "Certificate" section shows values decoded from the
// certificate bytes (GET certificates/{id}/details), never the record columns.
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { plugins, stubFetch, type Reply } from './helpers'
import CertificateDetails from '@/views/certificates/CertificateDetails.vue'
import Certificates from '@/views/certificates/index.vue'
import type { CertificateDetailsResult } from '@/api/types'

const SHA256 = 'AB:'.repeat(31) + 'CD'
const SHA1 = '12:'.repeat(19) + '34'
const decoded = (over: Partial<NonNullable<CertificateDetailsResult['details']>> = {}): CertificateDetailsResult => ({
  available: true,
  source: 'certificate',
  details: {
    subject: { dn: 'CN=api.example.org,O=Example', cn: 'api.example.org' },
    issuer: { dn: 'CN=Test Root CA,O=Tangra', cn: 'Test Root CA' },
    self_signed: false,
    serial: '0A:BC:DE:F0',
    version: 3,
    validity: { not_before: '2026-09-01T00:00:00Z', not_after: '2027-03-01T08:30:00Z', status: 'valid', days_remaining: 151 },
    sans: { dns: ['api.example.org', 'www.example.org'], ip: ['10.0.0.7'], uri: ['spiffe://example.org/ns/prod/sa/api', 'https://api.example.org/id'], spiffe: ['spiffe://example.org/ns/prod/sa/api'], email: ['ops@example.org'] },
    public_key: { algorithm: 'ECDSA', size: 256, curve: 'P-256' },
    signature_algorithm: 'ECDSA-SHA384',
    key_usage: ['Digital Signature'],
    ext_key_usage: ['Server Authentication', 'Client Authentication'],
    basic_constraints: { present: true, ca: false },
    subject_key_id: 'DE:AD:BE:EF',
    authority_key_id: '01:02',
    crl_distribution_points: ['http://crl.example.org/root.crl'],
    ocsp_servers: ['http://ocsp.example.org'],
    issuing_certificate_urls: [],
    fingerprints: { sha256: SHA256, sha1: SHA1 },
    chain: [{ subject: { dn: 'CN=Test Root CA', cn: 'Test Root CA' }, issuer: { dn: 'CN=Test Root CA', cn: 'Test Root CA' }, not_after: '2036-01-01T00:00:00Z', fingerprint_sha256: 'EE:FF' }],
    ...over,
  },
})

const mountDetails = (id = 'c1') => mount(CertificateDetails, { props: { certificateId: id }, global: { plugins: plugins() }, attachTo: document.body })
const text = (w: ReturnType<typeof mountDetails>, t: string) => w.find(`[data-test="${t}"]`).text()

beforeEach(() => setActivePinia(createPinia()))

describe('certificate details section', () => {
  it('renders the decoded values, grouped, with dates in the viewer locale and a validity badge', async () => {
    const calls = stubFetch(() => ({ status: 200, body: decoded() }))
    const w = mountDetails()
    expect(w.find('[data-test="cert-details-loading"]').exists()).toBe(true)
    await flushPromises()
    expect(String(calls.mock.calls[0]![0])).toBe('/api/lcm/v1/certificates/c1/details')
    expect(text(w, 'cert-details-caption')).toContain('Read from the certificate itself')
    expect(text(w, 'cert-details-subject-cn')).toBe('api.example.org')
    expect(text(w, 'cert-details-subject-dn')).toBe('CN=api.example.org,O=Example')
    expect(text(w, 'cert-details-issuer')).toContain('Test Root CA')
    expect(text(w, 'cert-details-serial')).toBe('0A:BC:DE:F0')
    expect(text(w, 'cert-details-not-after')).toBe(new Date('2027-03-01T08:30:00Z').toLocaleString())
    expect(w.find('[data-test="cert-details-not-after"]').attributes('title')).toBe('2027-03-01T08:30:00Z')
    expect(text(w, 'cert-details-validity')).toBe('Valid · 151 days remaining')
    expect(text(w, 'cert-details-san-dns')).toContain('www.example.org')
    expect(text(w, 'cert-details-san-ip')).toBe('10.0.0.7')
    expect(text(w, 'cert-details-san-spiffe')).toBe('spiffe://example.org/ns/prod/sa/api')
    // SPIFFE IDs are listed once, not again under URI.
    expect(text(w, 'cert-details-san-uri')).toBe('https://api.example.org/id')
    expect(text(w, 'cert-details-san-email')).toBe('ops@example.org')
    expect(text(w, 'cert-details-public-key')).toBe('ECDSA · 256 bit · P-256')
    expect(text(w, 'cert-details-signature')).toBe('ECDSA-SHA384')
    expect(text(w, 'cert-details-eku')).toContain('Client Authentication')
    expect(text(w, 'cert-details-basic-constraints')).toBe('End entity (CA: false)')
    expect(text(w, 'cert-details-ski')).toBe('DE:AD:BE:EF')
    expect(text(w, 'cert-details-sha256')).toBe(SHA256)
    expect(text(w, 'cert-details-chain')).toContain('Test Root CA')
    expect(w.text()).toContain('http://ocsp.example.org')
    w.unmount()
  })

  it('shows a CA path length and expired / not-yet-valid badges', async () => {
    const replies: Reply[] = [
      { status: 200, body: decoded({ basic_constraints: { present: true, ca: true, path_len: 1 }, validity: { not_before: '2020-01-01T00:00:00Z', not_after: '2026-09-27T00:00:00Z', status: 'expired', days_remaining: -4 } }) },
      { status: 200, body: decoded({ basic_constraints: { present: true, ca: true }, validity: { not_before: '2030-01-01T00:00:00Z', not_after: '2031-01-01T00:00:00Z', status: 'not_yet_valid', days_remaining: 1000 } }) },
    ]
    stubFetch(() => replies.shift()!)
    const w = mountDetails('a')
    await flushPromises()
    expect(text(w, 'cert-details-basic-constraints')).toBe('CA: true · path length 1')
    expect(text(w, 'cert-details-validity')).toBe('Expired · expired 4 days ago')
    await w.setProps({ certificateId: 'b' })
    await flushPromises()
    expect(text(w, 'cert-details-basic-constraints')).toBe('CA: true · path length unlimited')
    expect(text(w, 'cert-details-validity')).toContain('Not yet valid')
    w.unmount()
  })

  it('copies the fingerprints and serial with the kit copy button', async () => {
    stubFetch(() => ({ status: 200, body: decoded() }))
    const writeText = vi.fn(async () => {})
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    const w = mountDetails()
    await flushPromises()
    await w.find('[data-test="cert-details-copy-sha256"]').trigger('click')
    await w.find('[data-test="cert-details-copy-sha1"]').trigger('click')
    await w.find('[data-test="cert-details-copy-serial"]').trigger('click')
    await flushPromises()
    expect(writeText.mock.calls.map((c) => (c as unknown[])[0])).toEqual([SHA256, SHA1, '0A:BC:DE:F0'])
    w.unmount()
  })

  it('an undecodable certificate shows the reason; a failed load shows an error with retry', async () => {
    const replies: Reply[] = [
      { status: 200, body: { available: false, source: 'certificate', error: 'details_unavailable', reason: 'the stored data contains no PEM CERTIFICATE block' } },
      { status: 500, body: { reason: 'internal' } },
      { status: 200, body: decoded() },
    ]
    stubFetch(() => replies.shift()!)
    const w = mountDetails('x')
    await flushPromises()
    expect(text(w, 'cert-details-unavailable')).toContain('no PEM CERTIFICATE block')
    expect(w.find('[data-test="cert-details-serial"]').exists()).toBe(false)
    await w.setProps({ certificateId: 'y' })
    await flushPromises()
    expect(w.find('[data-test="cert-details-error"]').exists()).toBe(true)
    await w.find('[data-test="cert-details-retry"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="cert-details-error"]').exists()).toBe(false)
    expect(text(w, 'cert-details-serial')).toBe('0A:BC:DE:F0')
    w.unmount()
  })
})

describe('certificate drawer', () => {
  it('shows the decoded validity, not the record columns', async () => {
    class FakeSource { onopen = null; onerror = null; addEventListener() {} close() {} }
    vi.stubGlobal('EventSource', FakeSource)
    // The record says 2030 and a different subject; the certificate says otherwise.
    const row = { id: 'c1', serial: 'db-serial', subject: 'CN=column-subject', not_after: '2030-01-01T00:00:00Z', fingerprint_sha256: 'column-fp', spiffe_id: 'spiffe://example.org/svc/api', status: 'active', permissions: { write: true } }
    stubFetch((url) => {
      if (url.endsWith('/certificates/c1/details')) return { status: 200, body: decoded() }
      if (url.includes('/certificates')) return { status: 200, body: { items: [row], total: 1, page: 1, page_size: 25 } }
      return { status: 200, body: { items: [] } }
    })
    const w = mount(Certificates as never, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    await w.find('[data-test="cert-row-c1"]').trigger('click')
    await flushPromises()
    const drawer = document.body.querySelector('[data-test="certificate-drawer"]')!
    const details = drawer.querySelector('[data-test="cert-details"]')!
    expect(details.querySelector('[data-test="cert-details-not-after"]')!.textContent).toBe(new Date('2027-03-01T08:30:00Z').toLocaleString())
    expect(drawer.textContent).not.toContain(new Date('2030-01-01T00:00:00Z').toLocaleString())
    expect(drawer.textContent).not.toContain('column-subject')
    expect(drawer.textContent).not.toContain('column-fp')
    expect(drawer.textContent).not.toContain('db-serial')
    w.unmount()
  })
})
