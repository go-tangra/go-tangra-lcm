import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { AcmeInput, Certificate, CertificateBundle, CertificateFilter, CertificateUpdate, IssueInput, Page } from '@/api/types'

export const useCertificates = defineStore('lcm-certificates', () => {
  const items = ref<Certificate[]>([])
  const next = ref<string | undefined>()
  const loading = ref(false)
  const error = ref('')

  async function list(filter: CertificateFilter = {}, cursor?: string): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const page = await api<Page<Certificate>>('GET', 'certificates', undefined, { query: { ...filter, cursor, limit: 50 } })
      items.value = cursor ? [...items.value, ...page.items] : page.items
      next.value = page.next_cursor
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

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
    if (bundle.certificate) items.value = [bundle.certificate, ...items.value.filter((c) => c.id !== bundle.certificate.id)]
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
   * Reflects a live stream event in the list without a refetch. `issued` and
   * `renewed` carry a Certificate; `revoked` carries at least an id.
   */
  function upsert(c: Certificate): void {
    items.value = [c, ...items.value.filter((x) => x.id !== c.id)]
  }

  function applyEvent(type: string, data: unknown): void {
    const obj = (data ?? {}) as Partial<Certificate> & { id?: string; certificate?: Certificate; certificate_id?: string }
    const cert = (obj.certificate ?? obj) as Certificate
    const id = cert.id ?? obj.id ?? obj.certificate_id
    if (type === 'certificate.issued' || type === 'certificate.renewed') {
      if (cert.id) {
        upsert(cert)
      } else if (id) {
        // Lifecycle events carry only ids (issued via the async ACME path or the
        // renew scheduler); fetch the full row so the list reflects it live.
        void get(id).then(upsert).catch(() => {})
      }
    } else if (type === 'certificate.revoked') {
      if (!id) return
      items.value = items.value.map((c) => (c.id === id ? { ...c, status: 'revoked' } : c))
    }
  }

  return { items, next, loading, error, list, get, issue, obtainAcme, renew, revoke, update, remove, deploy, download, downloadKey, applyEvent }
})
