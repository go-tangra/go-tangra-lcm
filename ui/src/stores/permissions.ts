import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'
import type { Certificate, Effective, Grant, GrantInput, Issuer, ResourceType } from '@/api/types'
import { CERTIFICATE_LIST, ISSUER_LIST, listSpec, pagedList } from '@/stores/paged'

// The Permissions view pages the certificates and issuers the caller may read
// (its own tables: their page / sort live under ?perm-certificates.… and
// ?perm-issuers.…, independent of the Certificates and Issuers views).
export const PERM_CERTIFICATE_LIST = listSpec(['identity', 'created_at'], 'identity')
export const PERM_ISSUER_LIST = listSpec(['name', 'trust_domain'], 'name')
export const usePermCertificates = defineStore('lcm-perm-certificates', () => pagedList<Certificate>('certificates', { ...CERTIFICATE_LIST.first, ...PERM_CERTIFICATE_LIST.first }))
export const usePermIssuers = defineStore('lcm-perm-issuers', () => pagedList<Issuer>('issuers', { ...ISSUER_LIST.first, ...PERM_ISSUER_LIST.first }))

// Grants and effective access over a certificate or issuer (Zanzibar
// owner/editor/viewer/sharer), served by /grants and /access/*.
export const usePermissions = defineStore('lcm-permissions', () => {
  const grants = ref<Grant[]>([])
  const effective = ref<Effective | null>(null)
  const loading = ref(false)
  const error = ref('')

  async function load(resourceType: ResourceType, resourceId: string): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const [g, e] = await Promise.all([
        api<{ items: Grant[] }>('GET', 'grants', undefined, { query: { resource_type: resourceType, resource_id: resourceId } }).catch(() => ({ items: [] as Grant[] })),
        api<Effective>('GET', 'access/effective', undefined, { query: { resource_type: resourceType, resource_id: resourceId } }).catch(() => null),
      ])
      grants.value = g.items
      effective.value = e
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      loading.value = false
    }
  }

  async function grant(input: GrantInput): Promise<Grant> {
    const g = await api<Grant>('POST', 'grants', input)
    grants.value = [g, ...grants.value.filter((x) => !(x.subject_type === g.subject_type && x.subject_id === g.subject_id))]
    return g
  }

  async function revoke(id: string): Promise<void> {
    await api('POST', 'grants/' + id + '/revoke')
    grants.value = grants.value.filter((x) => x.id !== id)
  }

  return { grants, effective, loading, error, load, grant, revoke }
})
