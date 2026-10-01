import { defineStore } from 'pinia'
import { api } from '@/api/client'
import type { AcmeInput, Certificate, CertificateBundle, CertificateFilter, CertificateUpdate, IssueInput } from '@/api/types'
import { CERTIFICATE_LIST, listSpec, pagedList } from '@/stores/paged'

/** The dashboard's "expiring soon" preview: the first page by expiry (its own list state). */
export const EXPIRING_LIST = listSpec(['not_after'], 'not_after', 'asc', 10)
export const useExpiringCertificates = defineStore('lcm-expiring-certificates', () => pagedList<Certificate, CertificateFilter>('certificates', EXPIRING_LIST.first))

// The certificates table is one server page (list contract): page, size and
// sort travel to the server, the total counts only the certificates the
// caller may read. Live events reload the current page (debounced in the
// live store) instead of inserting rows client-side, which would ignore the
// sort and the page boundaries.
export const useCertificates = defineStore('lcm-certificates', () => {
  const page = pagedList<Certificate, CertificateFilter>('certificates', CERTIFICATE_LIST.first)
  const { items, total, params, filter, loading, loaded, error, list, reload } = page

  async function get(id: string): Promise<Certificate> {
    return api<Certificate>('GET', 'certificates/' + id)
  }

  /**
   * Request an SVID certificate. Issuance is asynchronous: the server accepts
   * the request (202) and reports the outcome over SSE (certificate.issued |
   * certificate.failed), which updates this list live. A generated key is
   * retained and downloadable from the certificate afterwards.
   */
  async function issue(input: IssueInput): Promise<{ status: string; spiffe_id: string }> {
    return api<{ status: string; spiffe_id: string }>('POST', 'certificates/issue', input)
  }

  /**
   * Request a generic (kind=generic) certificate from an ACME issuer. Issuance
   * is asynchronous: the server accepts the request (202) and reports the
   * outcome over SSE (certificate.issued | certificate.failed), which updates
   * this list live. The order is recorded as a request (request_id) that ends
   * issued or failed with the reason. Returns the acknowledgement, not a bundle.
   */
  async function obtainAcme(input: AcmeInput): Promise<{ status: string; domains: string[]; request_id?: string }> {
    return api<{ status: string; domains: string[]; request_id?: string }>('POST', 'certificates/acme', input)
  }

  async function renew(id: string): Promise<CertificateBundle> {
    const bundle = await api<CertificateBundle>('POST', 'certificates/' + id + '/renew')
    void reload() // the renewal is a new row: its place depends on the sort
    return bundle
  }

  async function revoke(id: string, reason?: string): Promise<void> {
    await api('POST', 'certificates/' + id + '/revoke', reason ? { reason } : {})
    items.value = items.value.map((c) => (c.id === id ? { ...c, status: 'revoked' } : c))
  }

  async function update(id: string, patch: CertificateUpdate): Promise<Certificate> {
    const c = await api<Certificate>('PUT', 'certificates/' + id, patch)
    items.value = items.value.map((x) => (x.id === id ? c : x))
    return c
  }

  async function remove(id: string): Promise<void> {
    await api('POST', 'certificates/' + id + '/remove')
    items.value = items.value.filter((c) => c.id !== id)
    void reload() // the next page's first row moves up
  }

  async function deploy(id: string, targetId: string): Promise<unknown> {
    return api('POST', 'certificates/' + id + '/deploy', { target_id: targetId })
  }

  /** The download endpoint returns the bundle without the private key. */
  async function download(id: string): Promise<CertificateBundle> {
    return api<CertificateBundle>('GET', 'certificates/' + id + '/download')
  }

  /** Retrieve the retained private key (generic certs whose key lcm stores). */
  async function downloadKey(id: string): Promise<string> {
    const res = await api<{ key_pem: string }>('GET', 'certificates/' + id + '/key')
    return res.key_pem
  }

  /**
   * Reflects a live stream event on the visible page in place where it cannot
   * move the row (a revocation's status); the caller reloads the page for
   * everything else (debounced, see the live store).
   */
  function applyEvent(type: string, data: unknown): void {
    const obj = (data ?? {}) as Partial<Certificate> & { id?: string; certificate?: Certificate; certificate_id?: string }
    const cert = (obj.certificate ?? obj) as Partial<Certificate>
    const id = cert.id ?? obj.id ?? obj.certificate_id
    if (type === 'certificate.revoked' && id) items.value = items.value.map((c) => (c.id === id ? { ...c, status: 'revoked' } : c))
  }

  return { items, total, params, filter, loading, loaded, error, list, reload, get, issue, obtainAcme, renew, revoke, update, remove, deploy, download, downloadKey, applyEvent }
})
