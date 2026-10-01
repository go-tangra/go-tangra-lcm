// The certificate drawer's "Certificate" section shows values decoded from the
// certificate bytes (GET certificates/{id}/details), never the record columns.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { plugins, stubFetch, type Reply } from './helpers'
import CertificateDetails from '@/views/certificates/CertificateDetails.vue'
import Certificates from '@/views/certificates/index.vue'
import type { CertificateDetailsResult } from '@/api/types'
import { durationLabel, hexGroups, isWebURL, keyLabel, parseDN, widthClass } from '@/views/certificates/certDetailsFormat'

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

const tab = (w: ReturnType<typeof mountDetails>, name: RegExp) => {
  const t = w.findAll('[role="tab"]').find((b) => name.test(b.text()))
  if (!t) throw new Error('no tab ' + name)
  return t
}
const open = async (w: ReturnType<typeof mountDetails>, name: RegExp) => {
  await tab(w, name).trigger('click')
  await flushPromises()
}
const withValidity = (validity: NonNullable<CertificateDetailsResult['details']>['validity']) => decoded({ validity })

describe('certificate details section', () => {
  // A fixed "today" inside the fixture's validity window (2026-09-01 → 2027-03-01).
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-10-01T00:00:00Z'))
  })
  afterEach(() => vi.useRealTimers())

  it('renders a summary card and the overview tab from the decoded certificate', async () => {
    const calls = stubFetch(() => ({ status: 200, body: decoded() }))
    const w = mountDetails()
    expect(w.find('[data-test="cert-details-loading"]').exists()).toBe(true)
    await flushPromises()
    expect(String(calls.mock.calls[0]![0])).toBe('/api/lcm/v1/certificates/c1/details')
    expect(text(w, 'cert-details-caption')).toContain('Read from the certificate itself')
    // Summary
    expect(text(w, 'cert-details-title')).toBe('api.example.org')
    expect(text(w, 'cert-details-subtitle')).toBe('Issued by Test Root CA')
    expect(text(w, 'cert-details-validity')).toBe('Valid')
    expect(text(w, 'cert-details-validity-hint')).toBe('151 days left')
    expect(text(w, 'cert-details-key-chip')).toBe('ECDSA P-256')
    expect(w.find('[data-test="cert-details-ca-chip"]').exists()).toBe(false)
    expect(w.find('[data-test="cert-details-self-signed-chip"]').exists()).toBe(false)
    // Overview (default tab)
    expect(tab(w, /^Overview/).attributes('aria-selected')).toBe('true')
    expect(w.find('[role="tabpanel"]').attributes('aria-labelledby')).toBe('tab-cert-overview')
    expect(text(w, 'cert-details-subject-cn')).toBe('api.example.org')
    expect(text(w, 'cert-details-subject')).toContain('Organization')
    expect(text(w, 'cert-details-subject')).toContain('Example')
    expect(text(w, 'cert-details-subject-dn')).toBe('CN=api.example.org,O=Example')
    expect(text(w, 'cert-details-issuer')).toContain('Test Root CA')
    expect(text(w, 'cert-details-issuer-dn')).toBe('CN=Test Root CA,O=Tangra')
    expect(text(w, 'cert-details-serial')).toBe('0A:BC:DE:F0')
    expect(text(w, 'cert-details-version')).toBe('X.509 v3')
    expect(text(w, 'cert-details-not-after')).toBe(new Date('2027-03-01T08:30:00Z').toLocaleString())
    expect(w.find('[data-test="cert-details-not-after"]').attributes('title')).toBe('2027-03-01T08:30:00Z')
    expect(w.find('[data-test="cert-details-not-before"]').attributes('title')).toBe('2026-09-01T00:00:00Z')
    expect(text(w, 'cert-details-duration')).toBe('181 days')
    w.unmount()
  })

  it('labels the Names and Chain tabs with counts and switches panels by click and keyboard', async () => {
    stubFetch(() => ({ status: 200, body: decoded() }))
    const w = mountDetails()
    await flushPromises()
    // 2 DNS + 1 IP + 1 SPIFFE + 1 other URI + 1 email; leaf + 1 stored chain cert.
    expect(tab(w, /^Names/).text()).toBe('Names6')
    expect(tab(w, /^Chain/).text()).toBe('Chain2')

    await open(w, /^Names/)
    expect(tab(w, /^Names/).attributes('aria-selected')).toBe('true')
    expect(w.find('[data-test="cert-details-subject-cn"]').exists()).toBe(false)
    expect(text(w, 'cert-details-san-dns')).toContain('www.example.org')
    expect(text(w, 'cert-details-san-ip')).toBe('10.0.0.7')
    expect(text(w, 'cert-details-san-spiffe')).toBe('spiffe://example.org/ns/prod/sa/api')
    // SPIFFE IDs are listed once, not again under URI.
    expect(text(w, 'cert-details-san-uri')).toBe('https://api.example.org/id')
    expect(text(w, 'cert-details-san-email')).toBe('ops@example.org')

    // Arrow keys move along the tablist (kit roving focus).
    await tab(w, /^Names/).trigger('keydown', { key: 'ArrowRight' })
    await flushPromises()
    expect(tab(w, /^Key/).attributes('aria-selected')).toBe('true')
    expect(text(w, 'cert-details-public-key')).toBe('ECDSA P-256')
    expect(text(w, 'cert-details-signature')).toBe('ECDSA-SHA384')
    expect(text(w, 'cert-details-key-usage')).toBe('Digital Signature')
    expect(text(w, 'cert-details-eku')).toContain('Client Authentication')
    expect(text(w, 'cert-details-basic-constraints')).toBe('End entity (CA: false)')

    await open(w, /^Extensions/)
    expect(text(w, 'cert-details-ski')).toBe('DE:AD:BE:EF')
    expect(text(w, 'cert-details-aki')).toBe('01:02')
    const ocsp = w.find('[data-test="cert-details-url-ocsp"] a')
    expect(ocsp.attributes('href')).toBe('http://ocsp.example.org')
    expect(ocsp.attributes('rel')).toBe('noopener noreferrer')
    expect(text(w, 'cert-details-url-issuers')).toBe('None')

    await open(w, /^Fingerprints/)
    // Grouped for reading, but the text is still the exact fingerprint.
    expect(text(w, 'cert-details-sha256')).toBe(SHA256)
    expect(w.findAll('[data-test="cert-details-sha256"] span')).toHaveLength(8)
    expect(text(w, 'cert-details-sha1')).toBe(SHA1)
    w.unmount()
  })

  it('renders the chain leaf → root with expiry badges and the chain error', async () => {
    const inter = { subject: { dn: 'CN=Issuing CA', cn: 'Issuing CA' }, issuer: { dn: 'CN=Test Root CA', cn: 'Test Root CA' }, not_after: '2026-10-11T00:00:00Z', fingerprint_sha256: '11:22:33:44:55:66:77:88' }
    const root = { subject: { dn: 'CN=Test Root CA', cn: 'Test Root CA' }, issuer: { dn: 'CN=Test Root CA', cn: 'Test Root CA' }, not_after: '2026-01-01T00:00:00Z', fingerprint_sha256: 'EE:FF' }
    stubFetch(() => ({ status: 200, body: decoded({ chain: [inter, root], chain_error: 'a chain certificate could not be parsed' }) }))
    const writeText = vi.fn(async () => {})
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    const w = mountDetails()
    await flushPromises()
    expect(tab(w, /^Chain/).text()).toBe('Chain3')
    await open(w, /^Chain/)
    const items = w.findAll('[data-test="cert-details-chain"] > li')
    expect(items.map((li) => li.find('[data-test="cert-details-chain-subject"]').text())).toEqual(['api.example.org', 'Issuing CA', 'Test Root CA'])
    expect(items[0]!.text()).toContain('This certificate')
    expect(items[1]!.text()).toContain('Intermediate')
    expect(items[2]!.text()).toContain('Root')
    expect(items.map((li) => li.find('[data-test="cert-details-chain-badge"]').text())).toEqual(['Valid', 'Expires in 10 days', 'Expired'])
    expect(items[1]!.text()).toContain('11:22:33:44:55:66…')
    expect(text(w, 'cert-details-chain-error')).toContain('could not be parsed')
    await w.find('[data-test="cert-details-copy-chain-1"]').trigger('click')
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith('11:22:33:44:55:66:77:88')
    w.unmount()
  })

  it('shows valid / expiring soon / expired / not yet valid in the summary, with the timeline position', async () => {
    const replies: Reply[] = [
      { status: 200, body: decoded() },
      { status: 200, body: withValidity({ not_before: '2026-07-03T00:00:00Z', not_after: '2026-10-31T00:00:00Z', status: 'valid', days_remaining: 30 }) },
      { status: 200, body: decoded({ basic_constraints: { present: true, ca: true, path_len: 1 }, self_signed: true, validity: { not_before: '2020-01-01T00:00:00Z', not_after: '2026-09-27T00:00:00Z', status: 'expired', days_remaining: -4 } }) },
      { status: 200, body: decoded({ basic_constraints: { present: true, ca: true }, validity: { not_before: '2026-10-11T00:00:00Z', not_after: '2031-01-01T00:00:00Z', status: 'not_yet_valid', days_remaining: 1553 } }) },
    ]
    stubFetch(() => replies.shift()!)
    const w = mountDetails('a')
    await flushPromises()
    const bar = () => w.find('[role="progressbar"]')
    const state = () => w.find('[data-test="cert-details-validity"]').attributes('data-state')
    // 30 of 181 days elapsed → 17 % (bar classes snap to 2 % steps).
    expect(state()).toBe('valid')
    expect(bar().attributes('aria-valuenow')).toBe('17')
    expect(w.find('[data-test="cert-details-progress"]').classes()).toContain('w-[16%]')
    expect(w.find('[data-test="cert-details-today"]').exists()).toBe(true)

    await w.setProps({ certificateId: 'b' })
    await flushPromises()
    expect(state()).toBe('expiring')
    expect(text(w, 'cert-details-validity')).toBe('Expiring soon')
    expect(text(w, 'cert-details-validity-hint')).toBe('30 days left')
    expect(bar().attributes('aria-valuenow')).toBe('75')

    await w.setProps({ certificateId: 'c' })
    await flushPromises()
    expect(state()).toBe('expired')
    expect(text(w, 'cert-details-validity')).toBe('Expired')
    expect(text(w, 'cert-details-validity-hint')).toBe('expired 4 days ago')
    expect(text(w, 'cert-details-subtitle')).toBe('Self-signed')
    expect(text(w, 'cert-details-ca-chip')).toBe('CA')
    expect(w.find('[data-test="cert-details-self-signed-chip"]').exists()).toBe(true)
    expect(bar().attributes('aria-valuenow')).toBe('100')
    expect(w.find('[data-test="cert-details-today"]').exists()).toBe(false)
    await open(w, /^Key/)
    expect(text(w, 'cert-details-basic-constraints')).toBe('CA: true · path length 1')

    await w.setProps({ certificateId: 'd' })
    await flushPromises()
    expect(state()).toBe('not_yet_valid')
    expect(text(w, 'cert-details-validity')).toBe('Not yet valid')
    expect(text(w, 'cert-details-validity-hint')).toBe('starts in 10 days')
    expect(bar().attributes('aria-valuenow')).toBe('0')
    // The selected tab survives switching certificates.
    expect(tab(w, /^Key/).attributes('aria-selected')).toBe('true')
    expect(text(w, 'cert-details-basic-constraints')).toBe('CA: true · path length unlimited')
    w.unmount()
  })

  it('falls back to a SAN for the title and shows None for empty groups', async () => {
    const body = decoded({ subject: { dn: '', cn: '' }, sans: { dns: [], ip: ['192.0.2.1'], uri: [], spiffe: [], email: [] }, key_usage: [], ext_key_usage: [], chain: [], public_key: { algorithm: 'RSA', size: 2048 } })
    delete body.details!.subject_key_id
    delete body.details!.authority_key_id
    stubFetch(() => ({ status: 200, body }))
    const w = mountDetails()
    await flushPromises()
    expect(text(w, 'cert-details-title')).toBe('192.0.2.1')
    expect(text(w, 'cert-details-key-chip')).toBe('RSA 2048')
    expect(tab(w, /^Chain/).text()).toBe('Chain1')
    await open(w, /^Key/)
    expect(text(w, 'cert-details-key-usage')).toBe('None')
    expect(text(w, 'cert-details-eku')).toBe('None')
    await open(w, /^Extensions/)
    expect(w.find('[data-test="cert-details-ski"]').exists()).toBe(false)
    await open(w, /^Chain/)
    expect(w.find('[data-test="cert-details-chain-none"]').exists()).toBe(true)
    w.unmount()
  })

  it('copies the fingerprints, serial and key IDs with the kit copy button', async () => {
    stubFetch(() => ({ status: 200, body: decoded() }))
    const writeText = vi.fn(async () => {})
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    const w = mountDetails()
    await flushPromises()
    await w.find('[data-test="cert-details-copy-serial"]').trigger('click')
    await open(w, /^Fingerprints/)
    await w.find('[data-test="cert-details-copy-sha256"]').trigger('click')
    await w.find('[data-test="cert-details-copy-sha1"]').trigger('click')
    await open(w, /^Extensions/)
    await w.find('[data-test="cert-details-copy-ski"]').trigger('click')
    await open(w, /^Names/)
    await w.find('[aria-label="Copy 10.0.0.7"]').trigger('click')
    await flushPromises()
    expect(writeText.mock.calls.map((c) => (c as unknown[])[0])).toEqual(['0A:BC:DE:F0', SHA256, SHA1, 'DE:AD:BE:EF', '10.0.0.7'])
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
    expect(w.find('[data-test="cert-details-summary"]').exists()).toBe(false)
    expect(w.find('[role="tablist"]').exists()).toBe(false)
    await w.setProps({ certificateId: 'y' })
    await flushPromises()
    expect(w.find('[data-test="cert-details-error"]').exists()).toBe(true)
    expect(w.find('[data-test="cert-details-summary"]').exists()).toBe(false)
    await w.find('[data-test="cert-details-retry"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="cert-details-error"]').exists()).toBe(false)
    expect(text(w, 'cert-details-serial')).toBe('0A:BC:DE:F0')
    w.unmount()
  })
})

describe('certificate details formatting', () => {
  it('splits RFC 2253 names with escapes and multi-valued RDNs', () => {
    expect(parseDN('CN=Doe\\, John+UID=jd,OU=R\\2BD,O=Acme,C=BG')).toEqual([
      { type: 'CN', label: 'Common name', value: 'Doe, John' },
      { type: 'UID', label: 'User ID', value: 'jd' },
      { type: 'OU', label: 'Organizational unit', value: 'R+D' },
      { type: 'O', label: 'Organization', value: 'Acme' },
      { type: 'C', label: 'Country', value: 'BG' },
    ])
    expect(parseDN('')).toEqual([])
  })
  it('groups hex pairs without changing the text, labels keys, durations and links', () => {
    expect(hexGroups('01:02:03:04:05:06')).toEqual(['01:02:03:04:', '05:06'])
    expect(keyLabel({ algorithm: 'Ed25519', size: 256 })).toBe('Ed25519')
    expect(keyLabel({ algorithm: 'RSA', size: 4096 })).toBe('RSA 4096')
    expect(durationLabel('2026-01-01T00:00:00Z', '2027-01-31T00:00:00Z')).toBe('395 days (1 year 30 days)')
    expect(widthClass(-5)).toBe('w-[0%]')
    expect(widthClass(101)).toBe('w-[100%]')
    expect(isWebURL('ldap://x/y')).toBe(false)
    expect(isWebURL('javascript:alert(1)')).toBe(false)
    expect(isWebURL('HTTPS://ocsp.example')).toBe(true)
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
    // The header is the decoded subject CN, not the record's identity (its SPIFFE id here).
    expect(drawer.querySelector('h2')!.textContent).toBe('api.example.org')
    w.unmount()
  })
})
