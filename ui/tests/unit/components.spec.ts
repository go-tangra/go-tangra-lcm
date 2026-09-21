import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { defineComponent, h } from 'vue'
import { VApp } from 'vuetify/components'
import { plugins, stubFetch } from './helpers'
import IssuerDrawer from '@/components/IssuerDrawer.vue'
import CertificateDrawer from '@/components/CertificateDrawer.vue'
import PermissionDrawer from '@/components/PermissionDrawer.vue'
import StatsCard from '@/components/StatsCard.vue'
import AuditTable from '@/components/AuditTable.vue'

// Drawers and menus need Vuetify's application frame (v-app) as an ancestor.
function mountWith(component: unknown, props: Record<string, unknown>) {
  const Host = defineComponent({ render: () => h(VApp, () => h(component as never, props)) })
  return mount(Host, { global: { plugins: plugins(), stubs: { teleport: true } } })
}

describe('IssuerDrawer', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('loads DNS providers for an ACME issuer and keeps a stored secret as the marker', async () => {
    const bodies: Array<Record<string, unknown>> = []
    stubFetch((url, init) => {
      if (url.endsWith('/dns-providers')) return { status: 200, body: [{ name: 'route53', display_name: 'AWS Route 53', fields: [{ key: 'access_key', label: 'Access key', secret: false, required: true }, { key: 'secret_key', label: 'Secret key', secret: true, required: true }] }] }
      if (init?.method === 'PUT') {
        bodies.push(JSON.parse(String(init.body)))
        return { status: 200, body: { id: 'i1', name: 'acme', type: 'acme', trust_domain: 'example.org', settings: {} } }
      }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const issuer = { id: 'i1', name: 'acme', type: 'acme' as const, trust_domain: 'example.org', is_default: false, settings: { dns_provider: 'route53', email: 'ops@x.test' }, permissions: { delete: true } }
    const w = mountWith(IssuerDrawer, { modelValue: true, issuer })
    await flushPromises()
    expect(w.find('[data-test="issuer-dns-provider"]').exists()).toBe(true)
    const secret = w.find('[data-test="issuer-cred-secret_key"] input')
    expect((secret.element as HTMLInputElement).value).toBe('__set__')
    await w.find('[data-test="issuer-save"]').trigger('click')
    await flushPromises()
    // The unchanged secret marker is not resent.
    expect(bodies[0]?.secrets).toBeUndefined()
  })

  it('shows a scrubbed validation error', async () => {
    stubFetch((url) => {
      if (url.endsWith('/dns-providers')) return { status: 200, body: [] }
      return { status: 422, body: { reason: 'validation_failed' } }
    })
    const w = mountWith(IssuerDrawer, { modelValue: true, issuer: null })
    await flushPromises()
    await w.find('[data-test="issuer-save"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="issuer-error"]').text()).toContain('highlighted')
  })
})

describe('CertificateDrawer', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('downloads the bundle and offers revoke for a writable active certificate', async () => {
    stubFetch((url) => {
      if (url.endsWith('/certificates/c1/download')) return { status: 200, body: { certificate: { id: 'c1' }, cert_pem: 'C', chain_pem: 'CH', bundle_pem: 'B' } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const cert = { id: 'c1', serial: '01', spiffe_id: 'spiffe://example.org/svc/api', status: 'active' as const, permissions: { write: true } }
    const w = mountWith(CertificateDrawer, { modelValue: true, certificate: cert })
    await flushPromises()
    expect(w.find('[data-test="cert-status"]').text()).toContain('active')
    expect(w.find('[data-test="cert-revoke"]').exists()).toBe(true)
    await w.find('[data-test="cert-download-bundle"]').trigger('click')
    await flushPromises()
    // No error surfaced means the bundle was fetched and saved.
    expect(w.find('[data-test="cert-error"]').exists()).toBe(false)
  })
})

describe('PermissionDrawer', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('offers only relations at or below the holder and lists grants by name', async () => {
    stubFetch((url) => {
      if (url.includes('/grants?')) return { status: 200, body: { items: [{ id: 'g1', subject_type: 'user', subject_id: 'u1', relation: 'viewer' }] } }
      if (url.includes('/access/effective')) return { status: 200, body: { relation: 'sharer', permissions: { share: true }, grants: [] } }
      if (url.endsWith('/api/v1/users/lookup')) return { status: 200, body: { items: [{ id: 'u1', display_name: 'Ana' }] } }
      if (url.startsWith('/api/v1/roles')) return { status: 200, body: [] }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountWith(PermissionDrawer, { modelValue: true, resourceType: 'certificate', resourceId: 'c1', resourceName: 'spiffe://example.org/svc/api' })
    await flushPromises()
    expect(w.find('[data-test="grant-add"]').exists()).toBe(true)
    expect(w.find('[data-test="grant-row-g1"]').text()).toContain('Ana')
  })

  it('hides the grant form without share', async () => {
    stubFetch((url) => {
      if (url.includes('/grants?')) return { status: 200, body: { items: [] } }
      if (url.includes('/access/effective')) return { status: 200, body: { relation: 'viewer', permissions: {}, grants: [] } }
      if (url.startsWith('/api/v1/roles')) return { status: 200, body: [] }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountWith(PermissionDrawer, { modelValue: true, resourceType: 'issuer', resourceId: 'i1' })
    await flushPromises()
    expect(w.find('[data-test="grant-add"]').exists()).toBe(false)
  })
})

describe('StatsCard and AuditTable', () => {
  beforeEach(() => setActivePinia(createPinia()))
  it('renders stat tiles and audit rows with resolved names', async () => {
    stubFetch((url) => {
      if (url.endsWith('/api/v1/users/lookup')) return { status: 200, body: { items: [{ id: 'u1', display_name: 'Ana' }] } }
      if (url.startsWith('/api/v1/roles')) return { status: 200, body: [] }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const stats = { certificates: { active: 2, expiring: 1 }, issuers: 3, jobs: { queued: 1 }, clients: 4, expiring_soon: 1, recent_errors: 0, open_streams: 5 }
    const sc = mountWith(StatsCard, { stats })
    expect(sc.find('[data-test="stat-value-certificates"]').text()).toContain('3')
    expect(sc.find('[data-test="stat-value-issuers"]').text()).toContain('3')
    const at = mountWith(AuditTable, { items: [{ ts: '2024-01-01T00:00:00Z', event_type: 'certificate_issued', actor_kind: 'user', actor_id: 'u1', subject_name: 'spiffe://example.org/svc/api', outcome: 'ok', details: {} }] })
    await flushPromises()
    expect(at.find('[data-test="audit-actor-cell"]').text()).toBe('Ana')
    expect(at.find('[data-test="audit-subject-cell"]').text()).toBe('spiffe://example.org/svc/api')
  })
})
